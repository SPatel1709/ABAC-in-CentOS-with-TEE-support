import argparse
import json
import os
import pwd
import stat
import subprocess
import sys
from pathlib import Path


ABAC_ROOT = Path("/sys/kernel/security/abac")
SECURED_DIR = Path("/home/secured")


def write_kernel_file(name, source_path):
    (ABAC_ROOT / name).write_text(Path(source_path).read_text())


def kernel_supports_hashmap():
    return (ABAC_ROOT / "hashmap").exists()


def append_attr(body, attr):
    if not body:
        return attr
    attrs = body.split(",")
    if attr in attrs:
        return body
    return body + "," + attr


def rewrite_dataset_user_for_runner(dataset_dir, run_as_user, benchmark_config=None):
    user = pwd.getpwnam(run_as_user)
    user_attr_path = Path(dataset_dir) / "user_attr"
    lines = user_attr_path.read_text().splitlines()

    if not lines:
        raise RuntimeError(f"{user_attr_path} is empty")

    first_uid, sep, attrs = lines[0].partition(":")
    if not sep:
        raise RuntimeError(f"Malformed user_attr entry: {lines[0]}")

    if benchmark_config and benchmark_config.get("guaranteed_read_allow_objects", 0) > 0:
        user_attr = benchmark_config.get("guaranteed_user_attr", "bench_user=allow")
        attrs = append_attr(attrs, user_attr)

    lines[0] = f"{user.pw_uid}:{attrs}"
    user_attr_path.write_text("\n".join(lines) + "\n")


def inject_mixed_workload(dataset_dir, benchmark_config):
    allow_object_count = benchmark_config.get("guaranteed_read_allow_objects", 0)

    if allow_object_count <= 0:
        return

    obj_attr = benchmark_config.get("guaranteed_object_attr", "bench_obj=allow")
    user_attr = benchmark_config.get("guaranteed_user_attr", "bench_user=allow")

    obj_attr_path = Path(dataset_dir) / "obj_attr"
    policy_path = Path(dataset_dir) / "policy"

    object_lines = obj_attr_path.read_text().splitlines()
    if not object_lines:
        raise RuntimeError(f"{obj_attr_path} is empty")

    for index in range(min(allow_object_count, len(object_lines))):
        path, sep, attrs = object_lines[index].partition(":")
        if not sep:
            raise RuntimeError(f"Malformed obj_attr entry: {object_lines[index]}")
        object_lines[index] = f"{path}:{append_attr(attrs, obj_attr)}"

    obj_attr_path.write_text("\n".join(object_lines) + "\n")

    policy_lines = policy_path.read_text().splitlines()
    guaranteed_rule = f"{user_attr}|{obj_attr}|*|READ"
    if guaranteed_rule not in policy_lines:
        policy_lines.insert(0, guaranteed_rule)
        policy_path.write_text("\n".join(policy_lines) + "\n")


def parse_stats():
    stats = {}
    for line in (ABAC_ROOT / "stats").read_text().strip().splitlines():
        key, value = line.split("=", 1)
        stats[key] = int(value)
    return stats


def ensure_secured_files(count, run_as_user):
    user = pwd.getpwnam(run_as_user)
    SECURED_DIR.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        path = SECURED_DIR / f"obj_{index}"
        path.write_text(f"object-{index}\n")
        os.chown(path, user.pw_uid, user.pw_gid)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)


def load_dataset(dataset_dir):
    write_kernel_file("policy", dataset_dir / "policy")
    write_kernel_file("user_attr", dataset_dir / "user_attr")
    write_kernel_file("obj_attr", dataset_dir / "obj_attr")
    write_kernel_file("env_attr", dataset_dir / "env_attr")


def run_access_test(run_as_user, object_count, iterations, seed):
    helper = Path(__file__).with_name("access_test.py").resolve()
    completed = subprocess.run(
        [
            "runuser",
            "-u",
            run_as_user,
            "--",
            sys.executable,
            str(helper),
            "--object-count",
            str(object_count),
            "--iterations",
            str(iterations),
            "--seed",
            str(seed),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def run_configuration(mode, hashmap_enabled, config, run_as_user):
    (ABAC_ROOT / "mode").write_text(mode + "\n")
    if kernel_supports_hashmap():
        (ABAC_ROOT / "hashmap").write_text(("on" if hashmap_enabled else "off") + "\n")
    (ABAC_ROOT / "action").write_text("RESET\n")

    if config.get("warmup_iterations", 0):
        run_access_test(
            run_as_user,
            config["obj"]["count"],
            config["warmup_iterations"],
            config.get("seed", 42),
        )

    (ABAC_ROOT / "action").write_text("RESET\n")
    (ABAC_ROOT / "action").write_text("RECORD\n")
    user_stats = run_access_test(
        run_as_user,
        config["obj"]["count"],
        config["iterations"],
        config.get("seed", 42),
    )
    (ABAC_ROOT / "action").write_text("STOP\n")
    kernel_stats = parse_stats()
    kernel_stats["mode"] = mode
    kernel_stats["hashmap_enabled"] = hashmap_enabled
    kernel_stats["last_access_ns"] = int((ABAC_ROOT / "perf").read_text().strip() or "0")
    return {
        "mode": mode,
        "hashmap_enabled": hashmap_enabled,
        "label": result_label(mode, hashmap_enabled),
        "user": user_stats,
        "kernel": kernel_stats,
    }


def result_label(mode, hashmap_enabled):
    if mode == "linear" and not hashmap_enabled:
        return "neither"
    if mode == "linear" and hashmap_enabled:
        return "hashmap_only"
    if mode == "tree" and not hashmap_enabled:
        return "tree_only"
    return "tree_and_hashmap"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True, help="Dataset directory produced by generate_dataset.py")
    parser.add_argument("--run-as-user", required=True, help="Non-root user to execute protected reads as")
    parser.add_argument("--results-dir", default="perf_eval/results")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("benchmark.py must be run as root")
    if not ABAC_ROOT.is_dir():
        sys.exit(f"{ABAC_ROOT} not found. Is the ABAC kernel loaded?")

    dataset_dir = Path(args.dataset)
    config = json.loads((dataset_dir / "config.json").read_text())
    benchmark_config = config.get("benchmark", {})

    ensure_secured_files(config["obj"]["count"], args.run_as_user)
    rewrite_dataset_user_for_runner(dataset_dir, args.run_as_user, benchmark_config)
    inject_mixed_workload(dataset_dir, benchmark_config)
    load_dataset(dataset_dir)

    results = {
        "dataset": str(dataset_dir),
        "config_name": config["name"],
        "iterations": config["iterations"],
        "hashmap_supported": kernel_supports_hashmap(),
        "modes": [],
    }

    configurations = [("linear", False), ("tree", False), ("linear", True), ("tree", True)]
    if not kernel_supports_hashmap():
        configurations = [("linear", False), ("tree", False)]

    for mode, hashmap_enabled in configurations:
        results["modes"].append(
            run_configuration(mode, hashmap_enabled, config, args.run_as_user)
        )

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    output = results_dir / f"{config['name']}.json"
    output.write_text(json.dumps(results, indent=2) + "\n")
    print(f"Results written to {output}")


if __name__ == "__main__":
    main()
