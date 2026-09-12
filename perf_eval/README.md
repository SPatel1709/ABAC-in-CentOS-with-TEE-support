# ABAC Performance Evaluation

This folder benchmarks the current `abac_lsm` implementation using the modern
policy format already accepted by `/sys/kernel/security/abac/`.

It compares the resolver and lookup-index combinations exposed by the kernel module:

- `linear`: linked-list rule scan
- `tree`: compiled policy-tree evaluation
- `hashmap=off`: linked-list user/object lookup
- `hashmap=on`: hash-indexed user/object lookup

## Files

- `generate_dataset.py`: builds synthetic ABAC datasets and serialized kernel
  input files
- `benchmark.py`: loads datasets, switches resolver modes and the hash-index
  flag, runs access tests, and saves JSON results
- `access_test.py`: helper executed as a non-root user so ABAC decisions are
  actually enforced
- `sample_config.json`: example benchmark configuration

## Typical Workflow

1. Generate a dataset:

```bash
python3 perf_eval/generate_dataset.py perf_eval/sample_config.json
```

2. Make sure:

- the patched kernel is booted
- `/sys/kernel/security/abac/` exists
- `/home/secured/` exists
- the benchmark user exists and belongs to the `abac` group

3. Run the benchmark as root:

```bash
python3 perf_eval/benchmark.py \
  --dataset perf_eval/generated/sample \
  --run-as-user abacbench
```

The benchmark writes the same dataset into the kernel, then runs the same
access workload across the four optimization combinations:

- `linear` + `hashmap=off`
- `linear` + `hashmap=on`
- `tree` + `hashmap=off`
- `tree` + `hashmap=on`

If the running kernel does not expose `/sys/kernel/security/abac/hashmap`, the
harness falls back to the original two-mode comparison. Results are written to
`perf_eval/results/`.
