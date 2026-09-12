import argparse
import json
import random
from pathlib import Path


def choose_subset(mapping, count):
    keys = list(mapping.keys())
    count = min(count, len(keys))
    selected = random.sample(keys, count)
    return {key: mapping[key] for key in selected}


def generate_policy(config):
    policy = []
    for rule_id in range(config["policy"]["count"]):
        user_avps = {
            f"ua_{idx}": f"ua_{idx}_v_{random.randrange(config['user']['values_per_attr'])}"
            for idx in random.sample(
                range(config["user"]["attrs"]),
                min(config["policy"]["user_attrs_per_rule"], config["user"]["attrs"]),
            )
        }
        obj_avps = {
            f"oa_{idx}": f"oa_{idx}_v_{random.randrange(config['obj']['values_per_attr'])}"
            for idx in random.sample(
                range(config["obj"]["attrs"]),
                min(config["policy"]["obj_attrs_per_rule"], config["obj"]["attrs"]),
            )
        }
        env_count = min(config["env"]["assigned_attrs_per_rule"], config["env"]["attrs"])
        env_avps = {
            f"ea_{idx}": f"ea_{idx}_v_{random.randrange(config['env']['values_per_attr'])}"
            for idx in random.sample(range(config["env"]["attrs"]), env_count)
        }
        effect = "DENY" if random.random() < config["policy"]["deny_ratio"] else "ALLOW"
        op = "MODIFY" if random.random() < 0.5 else "READ"
        policy.append(
            {
                "id": rule_id + 1,
                "user": user_avps,
                "obj": obj_avps,
                "env": env_avps,
                "op": op,
                "effect": effect,
            }
        )
    return policy


def generate_entities(config, policy):
    users = {}
    objects = {}

    policy_cycle = policy[:]
    random.shuffle(policy_cycle)

    for idx in range(config["user"]["count"]):
        rule = policy_cycle[idx % len(policy_cycle)]
        attrs = choose_subset(rule["user"], config["user"]["assigned_attrs_per_entity"])
        users[str(2000 + idx)] = attrs

    for idx in range(config["obj"]["count"]):
        rule = policy_cycle[idx % len(policy_cycle)]
        attrs = choose_subset(rule["obj"], config["obj"]["assigned_attrs_per_entity"])
        objects[f"/home/secured/obj_{idx}"] = attrs

    env = {
        f"ea_{idx}": f"ea_{idx}_v_{random.randrange(config['env']['values_per_attr'])}"
        for idx in range(config["env"]["attrs"])
    }

    if policy:
        for key, value in policy[0]["env"].items():
            env[key] = value

    return users, objects, env


def serialize_policy(policy):
    lines = []
    for rule in policy:
        user = ",".join(f"{key}={value}" for key, value in rule["user"].items())
        obj = ",".join(f"{key}={value}" for key, value in rule["obj"].items())
        env = ",".join(f"{key}={value}" for key, value in rule["env"].items()) or "*"
        line = f"{user}|{obj}|{env}|{rule['op']}"
        if rule["effect"] == "DENY":
            line += "|DENY"
        lines.append(line)
    return "\n".join(lines) + "\n"


def serialize_users(users):
    lines = []
    for uid, attrs in users.items():
        body = ",".join(f"{key}={value}" for key, value in attrs.items())
        lines.append(f"{uid}:{body}")
    return "\n".join(lines) + "\n"


def serialize_objects(objects):
    lines = []
    for path, attrs in objects.items():
        body = ",".join(f"{key}={value}" for key, value in attrs.items())
        lines.append(f"{path}:{body}")
    return "\n".join(lines) + "\n"


def serialize_env(env):
    return "\n".join(f"{key}={value}" for key, value in env.items()) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("config", help="Path to benchmark config JSON")
    args = parser.parse_args()

    config_path = Path(args.config)
    config = json.loads(config_path.read_text())
    random.seed(config.get("seed", 42))

    policy = generate_policy(config)
    users, objects, env = generate_entities(config, policy)

    out_dir = Path("perf_eval/generated") / config["name"]
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    (out_dir / "raw.json").write_text(
        json.dumps({"config": config, "policy": policy, "users": users, "objects": objects, "env": env}, indent=2)
        + "\n"
    )
    (out_dir / "policy").write_text(serialize_policy(policy))
    (out_dir / "user_attr").write_text(serialize_users(users))
    (out_dir / "obj_attr").write_text(serialize_objects(objects))
    (out_dir / "env_attr").write_text(serialize_env(env))

    print(f"Dataset written to {out_dir}")


if __name__ == "__main__":
    main()
