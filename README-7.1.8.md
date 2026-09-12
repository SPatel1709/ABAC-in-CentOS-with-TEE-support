# ABAC Fedora Port

This repository keeps the ABAC work in a form that is small enough to push while still preserving the kernel port.

## What Is In This Repo

- `abac_utils/`: userspace CLI and services
- `abac_lsm/`: original standalone ABAC LSM source snapshot
- `abac_lsm_2022-master/`: older upstream/reference source tree
- `kernel_patch/abac-linux-6.19.8.patch`: historical patch produced against Linux `6.19.8`; it has been successfully applied to and validated against a pristine Linux `7.1.8` source tree
- `PORTING_CHANGES.md`: notes describing the porting and runtime fixes

## What Is Not In This Repo

The full patched kernel tree and kernel tarball are intentionally not tracked because they are too large.

The current validated kernel is Linux `7.1.8`, producing the custom release `7.1.8-abac`.

To recreate the kernel side, start from a pristine Linux `6.19.8` source tree and apply the patch in `kernel_patch/`.

### Compatibility note

The repository's patch is named `abac-linux-6.19.8.patch` because that is the kernel version against which the port was originally prepared. For the current Fedora 44 setup, the patch was applied to Linux `7.1.8` and both a dry-run and the actual patch application succeeded. The resulting ABAC sources compiled successfully, and the installed `7.1.8-abac` kernel booted with the ABAC securityfs interface available under `/sys/kernel/security/abac/`.


### 1. Get a pristine Linux 7.1.8 tree

Download and extract the stock Linux `7.1.8` source from kernel.org or another trusted source.

Example:

```bash
tar -xf linux-7.1.8.tar.xz
cd linux-7.1.8
```

### 2. Apply the ABAC patch

From the kernel source root:

```bash
patch -p1 < /path/to/ABAC_Fedora/kernel_patch/abac-linux-6.19.8.patch
```

This patch:

- wires `security/abac` into `security/Kconfig`
- wires `security/abac` into `security/Makefile`
- adds the ABAC LSM source under `security/abac`
- includes the compatibility fixes originally developed for the modern `6.19.8` port and validated again on Linux `7.1.8`

### 3. Configure the kernel

Enable:

- `CONFIG_SECURITY`
- `CONFIG_SECURITYFS`
- `CONFIG_SECURITY_PATH`
- `CONFIG_SECURITY_ABAC`

You can use:

```bash
make menuconfig
```

### 4. Build and install the kernel

Example:

```bash
make -j"$(nproc)"
sudo make modules_install
sudo make install
```

### 5. Boot with ABAC enabled in the LSM list

Make sure your kernel command line includes `abac` in the `lsm=` parameter.

Example:

```text
lsm=lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm,abac
```

### 6. Verify the kernel side

After booting into the patched kernel:

```bash
uname -r
cat /sys/kernel/security/lsm
ls /sys/kernel/security/abac
dmesg | grep ABAC
```

Expected results:

- `abac` appears in `/sys/kernel/security/lsm`
- `/sys/kernel/security/abac/` exists
- files such as `policy`, `user_attr`, `obj_attr`, and `env_attr` are present

## Userspace Setup

### 1. Install `abac_utils`

From this repository:

```bash
cd abac_utils
sudo ./install.sh
```

### 2. Verify the CLI and services

```bash
which abac
systemctl status abac.service
systemctl status abac_env.service
systemctl status abac_watch.service
```

### 3. Load policy and attributes

The CLI writes config to `/etc/abac/` and loads data into:

- `/sys/kernel/security/abac/policy`
- `/sys/kernel/security/abac/user_attr`
- `/sys/kernel/security/abac/obj_attr`
- `/sys/kernel/security/abac/env_attr`

Useful commands:

```bash
sudo abac init
sudo abac load
abac obj list /home/secured/example.txt
```

## Implemented Features

This repository contains the ABAC work across three layers:

- the kernel patch in `kernel_patch/abac-linux-6.19.8.patch`
- the standalone ABAC source snapshot in `abac_lsm/`
- the userspace tooling in `abac_utils/`

One important detail is that the modern Linux `6.19.8` porting changes are preserved primarily in the kernel patch and in `PORTING_CHANGES.md`. The `abac_lsm/` tree is still useful as a readable source snapshot for the ABAC logic, but some of the newest kernel-registration changes are represented most accurately in the patch.

### Feature Summary

| Feature | Implemented? | What it does |
|---|---|---|
| Kernel patch and porting changes | Yes | Ports the original ABAC LSM to a modern Linux `7.1.8` kernel layout and integration model. |
| LSM registration port | Yes | Updates ABAC hook registration to the modern Linux Security Module registration style. |
| Securityfs initialization port | Yes | Ports creation of `/sys/kernel/security/abac` to the newer kernel initcall and error-handling expectations. |
| Correctness fixes | Yes | Fixes parsing and runtime issues that would otherwise produce incorrect behavior or broken kernel integration. |
| Runtime kernel interface | Yes | Exposes files in `securityfs` so policy, attributes, mode switches, and instrumentation can be controlled at runtime. |
| Userspace utilities and services | Yes | Provides CLI commands and background services for loading policy, managing attributes, and keeping runtime state in sync. |
| Negative rule support | Yes | Adds explicit deny rules so access can be blocked even when some allow rule also matches. |
| Compiled policy tree | Yes | Precompiles policy rules into a structured tree to reduce repeated linear scanning during access checks. |
| Runtime optimization flags | Yes | Lets the system switch between linear and tree-based resolution, and toggle hashmap-backed lookup. |
| Path scope support | Yes | Restricts ABAC enforcement to selected include paths, with optional exclude paths. |
| Directory-level object attribute inheritance | Yes | Allows attributes assigned to a directory to apply to descendant files and subdirectories unless overridden. |
| Kernel-side instrumentation | Yes | Records decision counts and timing information inside the kernel for measurement and analysis. |
| Benchmark harness | Yes | Runs repeatable performance tests across resolver modes and lookup strategies. |
| Hash-map indexed user and object lookup | Yes | Speeds up attribute lookup by using kernel hash tables instead of scanning linked lists. |

### Brief Feature Explanations

#### Kernel Patch and Porting Changes

The repository preserves the modern kernel integration as a patch against a pristine Linux `7.1.8` tree. This includes build-system wiring, ABAC source integration under `security/abac`, and compatibility fixes required by current kernel APIs.

#### LSM Registration Port

Linux Security Module registration changed significantly between older kernels and current ones. This port updates ABAC so its hooks are registered using the current LSM mechanism rather than the older style used by the original codebase.

#### Securityfs Initialization Port

ABAC exposes its runtime interface through `/sys/kernel/security/abac`. The initialization code was ported so this filesystem setup matches the newer kernel initcall expectations and returns proper error codes on failure.

#### Correctness Fixes

This work includes fixes that are not just about compilation. It also corrects behavior such as parsing and runtime handling so that policies and attributes are interpreted consistently and safely.

#### Runtime Kernel Interface

The kernel side exposes a writable and readable runtime interface through files such as:

- `policy`
- `user_attr`
- `obj_attr`
- `env_attr`
- `mode`
- `hashmap`
- `action`
- `perf`
- `stats`
- `include_paths`
- `exclude_paths`

These files let userspace load policies and attributes, switch optimization modes, control instrumentation, and configure ABAC path scope without rebuilding the kernel.

#### Userspace Utilities and Services

The `abac_utils/` package provides the operational tooling around the kernel module. It includes:

- a CLI for managing policy, users, objects, and attribute-value pairs
- a loader for writing policy and attributes into the kernel
- a service that manages object attributes
- a watcher service for configured shared directories

Together, these pieces make the kernel module usable as a system rather than just a kernel experiment.

#### Negative Rule Support

Negative rule support means the policy language can express explicit deny decisions, not only allow decisions. In practice, this lets a rule say that a matching user-object-operation combination must be denied, even if another rule would otherwise allow it.

#### Compiled Policy Tree

The compiled policy tree is an optimization for policy evaluation. Instead of checking every rule one by one on each access, the policy is reorganized into a structured form grouped by object attributes, operation, and matching conditions. This reduces repeated work during access checks and provides a faster comparison point against the original linear resolver.

#### Runtime Optimization Flags

The kernel exposes runtime controls that let evaluation strategy be changed without recompiling:

- `mode=linear` uses the original linked-list rule scan
- `mode=tree` uses the compiled policy-tree resolver
- `hashmap=on/off` enables or disables hash-indexed lookup for users and objects

This makes side-by-side performance evaluation possible on the same kernel and dataset.

#### Path Scope Support

Path scope support limits where ABAC policy is enforced. Rather than applying to every file on the system, ABAC can be configured to protect only selected include paths while skipping selected exclude paths. This makes deployment safer and more practical.

#### Directory-Level Object Attribute Inheritance

Object attributes can be attached to directories as well as individual files. When a directory has attributes, descendant paths inherit those attributes unless a more specific path overrides them. This reduces configuration duplication for large directory trees.

#### Kernel-Side Instrumentation

The kernel records timing and decision counters for ABAC checks. This includes values such as:

- number of decisions made
- number of allows and denies
- total time spent in decisions
- minimum, maximum, and previous access-check latency

This instrumentation is useful for performance analysis and for comparing resolver modes.

#### Benchmark Harness

The `perf_eval/` directory contains a benchmark harness that:

- generates or consumes serialized policy datasets
- loads those datasets into the kernel
- executes protected accesses as a non-root user
- compares linear and tree-based resolution
- compares linked-list and hashmap-backed lookup

The harness writes structured JSON results for later analysis.

#### Hash-Map Indexed User and Object Lookup

The original lookup flow scans linked lists to find user and object attributes. The hashmap optimization builds kernel hash tables keyed by UID and object path so those lookups can complete more quickly, especially as the dataset grows.

### Documentation-Only Sections

If you are mapping this repository to a thesis or report outline, the following sections are not separate software features:

- `Design Decisions`
- `Challenges Encountered`

Those are best treated as explanatory write-up sections rather than implementation targets.

## Recommended Repo Contents

For a normal push, keep:

- `README.md`
- `PORTING_CHANGES.md`
- `kernel_patch/`
- `abac_utils/`
- `abac_lsm/`
- `abac_lsm_2022-master/` if you want the original reference tree in the repo

If you want a smaller repo later, `abac_lsm_2022-master/` can also be removed and replaced with a link to the upstream source.

## Notes

- The kernel work is preserved as a patch so it can be reapplied to a clean Linux tree.
- `PORTING_CHANGES.md` explains the important fixes that were needed for the modern kernel and userspace runtime.
- The repo is intentionally structured to be pushable to GitHub without committing the full kernel source tree.
