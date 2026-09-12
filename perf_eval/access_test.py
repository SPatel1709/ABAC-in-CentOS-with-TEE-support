import argparse
import json
import random
import statistics
import sys
from pathlib import Path
from time import perf_counter_ns


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--object-count", type=int, required=True)
    parser.add_argument("--iterations", type=int, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--base-dir", default="/home/secured")
    parser.add_argument("--output", default="-")
    args = parser.parse_args()

    random.seed(args.seed)
    timings = []
    allowed = 0
    denied = 0

    for iteration in range(args.iterations):
        indices = list(range(args.object_count))
        random.shuffle(indices)
        for index in indices:
            target = Path(args.base_dir) / f"obj_{index}"
            start = perf_counter_ns()
            try:
                target.read_text()
                allowed += 1
            except PermissionError:
                denied += 1
            end = perf_counter_ns()
            timings.append(end - start)

    result = {
        "allowed": allowed,
        "denied": denied,
        "samples": len(timings),
        "user_time_total_ns": sum(timings),
        "user_time_mean_ns": statistics.mean(timings) if timings else 0,
        "user_time_median_ns": statistics.median(timings) if timings else 0,
        "user_time_min_ns": min(timings) if timings else 0,
        "user_time_max_ns": max(timings) if timings else 0,
    }
    payload = json.dumps(result, indent=2) + "\n"
    if args.output == "-":
        sys.stdout.write(payload)
    else:
        Path(args.output).write_text(payload)


if __name__ == "__main__":
    main()
