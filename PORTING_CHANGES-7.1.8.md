# ABAC Porting And Fixes Notes

This document summarizes the code changes made while porting the ABAC kernel module and userspace tools from the original `5.10.62` flow through the `6.19.8` port to a working modern-kernel setup on Fedora with a custom `7.1.8-abac` kernel.

It focuses on:

- what file was changed
- what problem was happening
- why the problem happened
- how it was resolved
- what was used to verify the fix

## Current Validation: Linux 7.1.8

The kernel patch was originally produced for the Linux `6.19.8` source layout. It was subsequently applied to a pristine Linux `7.1.8` source tree in Fedora 44 and the resulting `7.1.8-abac` kernel was built, installed, booted, and verified successfully.

No additional ABAC source changes were required for the tested Linux `7.1.8` tree beyond the changes already contained in the `6.19.8` port.

The historical patch filename remains `abac-linux-6.19.8.patch`; the filename identifies the original patch target and does not mean the current working kernel is `6.19.8`.

## Scope

The work covered two areas:

- Kernel-side ABAC LSM integration in [`linux-7.1.8-abac/security/abac`](/home/ojasdubey/abac/linux-7.1.8-abac/security/abac)
- Userspace ABAC utilities in [`abac_utils`](/home/ojasdubey/abac/abac_utils)

## High-Level Result

The final working state was:

- custom kernel `7.1.8-abac` booted successfully
- `abac` appeared in `/sys/kernel/security/lsm`
- `/sys/kernel/security/abac/` existed and exposed `policy`, `user_attr`, `obj_attr`, and `env_attr`
- userspace services installed and started successfully
- a test policy allowed `READ` and denied `MODIFY` exactly as expected

## Kernel Build-System Integration

### 1. [`linux-7.1.8-abac/security/Kconfig`](/home/ojasdubey/abac/linux-7.1.8-abac/security/Kconfig)

Change made:

```text
source "security/abac/Kconfig"
```

Problem:

- The modern kernel tree did not know that the ABAC LSM existed.
- Without this line, `CONFIG_SECURITY_ABAC` could not be selected in kernel configuration.

Resolution:

- Added the ABAC Kconfig source entry near the other LSM Kconfig entries.

Verification:

- `ABAC support` became visible in `make menuconfig`.

### 2. [`linux-7.1.8-abac/security/Makefile`](/home/ojasdubey/abac/linux-7.1.8-abac/security/Makefile)

Change made:

```text
obj-$(CONFIG_SECURITY_ABAC)		+= abac/
```

Problem:

- Even if `CONFIG_SECURITY_ABAC` was enabled, the ABAC objects would not be compiled unless the build system knew to descend into `security/abac/`.

Resolution:

- Added the build rule for the ABAC directory.

Verification:

- `make -j1 security/abac/` started compiling the ABAC sources.

## Kernel API Porting Changes

### 3. [`linux-7.1.8-abac/security/abac/abacfs.c`](/home/ojasdubey/abac/linux-7.1.8-abac/security/abac/abacfs.c)

Changes made:

- changed `abac_create_fs()` from `void` to `int`
- added `__init`
- returned `-ENOMEM` on securityfs creation failures
- returned `0` on success

Problem:

- The original code used:

```c
fs_initcall(abac_create_fs);
```

- On the modern kernel, initcall targets must match the expected initcall signature.
- Build error:

```text
static assertion failed: "__same_type(initcall_t, &abac_create_fs)"
```

Why it happened:

- Older kernel code accepted the original shape, but modern kernels perform stricter type checks on initcall functions.

Resolution:

- Updated the function to the expected initcall form.

Verification:

- `security/abac/abacfs.o` compiled successfully.
- On boot, `dmesg` showed:
  - `ABAC LSM: Created file /sys/kernel/security/abac/policy`
  - `ABAC LSM: Created file /sys/kernel/security/abac/user_attr`
  - `ABAC LSM: Created file /sys/kernel/security/abac/obj_attr`
  - `ABAC LSM: Created file /sys/kernel/security/abac/env_attr`
  - `ABAC LSM: Securityfs Initialized`

### 4. [`linux-7.1.8-abac/security/abac/abac.c`](/home/ojasdubey/abac/linux-7.1.8-abac/security/abac/abac.c)

Changes made:

- added:

```c
static struct lsm_id abac_lsmid __ro_after_init = {
	.name = "abac",
};
```

- changed `is_secured()` to:
  - `static`
  - `const char *` arguments
- removed unused helper `get_full_name()`
- changed:

```c
static struct security_hook_list abac_hooks[] __lsm_ro_after_init
```

to:

```c
static struct security_hook_list abac_hooks[] __ro_after_init
```

- changed:

```c
security_add_hooks(abac_hooks, ARRAY_SIZE(abac_hooks), "abac");
```

to:

```c
security_add_hooks(abac_hooks, ARRAY_SIZE(abac_hooks), &abac_lsmid);
```

- changed:

```c
DEFINE_LSM(abac) = {
	.init = abac_init,
	.name = "abac",
};
```

to:

```c
DEFINE_LSM(abac) = {
	.id = &abac_lsmid,
	.init = abac_init,
};
```

Problem:

- The modern LSM framework no longer matched the older registration API.
- The original code failed with errors around:
  - `__lsm_ro_after_init`
  - `security_add_hooks()`
  - `DEFINE_LSM`
  - `.name` not existing in the expected place

Why it happened:

- The Linux LSM registration interfaces changed between `5.10.62` and the modern kernel APIs used by the `6.19.8` port.
- The modern kernel expects a `struct lsm_id *` to identify the module when registering hooks.

Resolution:

- Ported the registration logic to the current LSM API pattern already used by modern in-tree LSMs like Yama and Lockdown.

Verification:

- `security/abac/abac.o` compiled successfully.
- After booting with:

```text
lsm=lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm,abac
```

- the following checks passed:

```bash
cat /proc/cmdline
cat /sys/kernel/security/lsm
sudo dmesg | grep ABAC
```

- `cat /sys/kernel/security/lsm` included `abac`
- `dmesg` showed:

```text
ABAC LSM: Initialized.
Files in /home/secured/ are protected by ABAC policy defined in rules.
```

### 5. [`linux-7.1.8-abac/security/abac/obj.c`](/home/ojasdubey/abac/linux-7.1.8-abac/security/abac/obj.c)

Changes made:

- removed unused local variable `i` in `parse_line()`
- changed:

```c
o->path[delim - start + 1] = '\0';
```

to:

```c
o->path[delim - start] = '\0';
```

Problem:

- There was a compiler warning for an unused variable.
- There was also an off-by-one null terminator on the copied path buffer.

Why it mattered:

- The warning was minor, but the path termination bug was a real correctness issue.
- It could leave an unexpected extra byte gap before the null terminator and was simply not the right index.

Resolution:

- Removed the dead variable and fixed the null terminator placement.

Verification:

- `security/abac/obj.o` compiled cleanly.
- Object attribute assignment and object-path matching worked during the policy test.

## Userspace Packaging And Dependency Fixes

### 6. [`abac_utils/setup.py`](/home/ojasdubey/abac/abac_utils/setup.py)

Change made:

- changed:

```python
install_requires = ["click", "watchdog", "apscheduler"]
```

to:

```python
install_requires = ["click", "watchdog", "APScheduler<4"]
```

Problem:

- The code in [`env_update.py`](/home/ojasdubey/abac/abac_utils/src/env_update.py) imports:

```python
from apscheduler.schedulers.blocking import BlockingScheduler
```

- The initial install pulled APScheduler `4.0.0a6`.
- APScheduler 4 changed the package layout, so that import path no longer existed.

Observed failure:

```text
ModuleNotFoundError: No module named 'apscheduler.schedulers'
```

Resolution:

- Pinned the dependency to the compatible major version family used by the existing code.

Verification:

```bash
python3 -c "from apscheduler.schedulers.blocking import BlockingScheduler; print('ok')"
```

- printed `ok`
- `abac env-update` then started successfully via systemd

### 7. [`abac_utils/install.sh`](/home/ojasdubey/abac/abac_utils/install.sh)

Change made:

Added:

```bash
python3 -m pip install "click" "watchdog" "APScheduler<4" >> /dev/null
```

before:

```bash
python3 setup.py install >> /dev/null
```

Problem:

- The installer still used `setup.py install`, which is a legacy flow and did not reliably produce the correct dependency environment on this machine.

Why it happened:

- The original installer predated current Python packaging practices.
- Even after fixing `setup.py`, the installed environment still needed the right version of APScheduler available before the console entrypoint ran.

Resolution:

- Added an explicit dependency installation step to ensure the runtime environment matched the code.

Verification:

- `sudo ./install.sh` completed successfully
- `abac init` ran without the APScheduler import failure
- systemd services installed and started

## Userspace Object-Attribute RPC Fixes

### 8. [`abac_utils/src/obj.py`](/home/ojasdubey/abac/abac_utils/src/obj.py)

Change made:

- added:

```python
AUTHKEY = b"abac-local"
```

- updated all `Client(...)` calls to:

```python
Client(address, authkey=AUTHKEY)
```

Problem:

- `abac obj add ...` and related object-management commands hung instead of prompting for attribute input.

Observed behavior:

- the command appeared to do nothing
- the server sometimes crashed with:

```text
OSError: got end of file during message
```

Why it happened:

- The code used `multiprocessing.connection.Client` and `Listener` without a stable shared authentication key.
- Different processes ended up using different default auth keys, which broke the handshake.

Resolution:

- Introduced an explicit shared `AUTHKEY` constant for the local object-attribute RPC channel.

Verification:

- `sudo abac obj add /home/secured/test.txt` began prompting correctly:
  - `Select new attribute from - type:`
  - `Select new value - type from [public, private]:`

### 9. [`abac_utils/src/server.py`](/home/ojasdubey/abac/abac_utils/src/server.py)

Changes made:

- added:

```python
AUTHKEY = b"abac-local"
```

- changed:

```python
with Listener(address) as listener:
```

to:

```python
with Listener(address, authkey=AUTHKEY) as listener:
```

- wrapped `conn.recv()` in:

```python
try:
    msg = conn.recv()
except OSError:
    continue
```

Problem:

- The server crashed when a client disconnected before a valid full message was received.

Observed failure:

```text
OSError: got end of file during message
```

Why it happened:

- The RPC handshake/path was fragile and the server treated EOF during message receipt as fatal.

Resolution:

- Matched the auth key to the client
- made the server ignore incomplete/aborted client connections instead of exiting

Verification:

- `abac.service` remained stable after retries
- object attribute management started working end-to-end

## Functional Verification Performed

The following functional checks were completed successfully:

### Kernel / LSM checks

```bash
uname -r
cat /proc/cmdline
cat /sys/kernel/security/lsm
sudo dmesg | grep ABAC
ls /sys/kernel/security/abac
```

Confirmed:

- custom kernel `7.1.8-abac` booted
- `abac` present in the active LSM list
- ABAC initialization messages appeared in `dmesg`
- securityfs files existed

### Userspace service checks

```bash
which abac
systemctl status abac.service
systemctl status abac_env.service
systemctl status abac_watch.service
```

Confirmed:

- CLI installed
- object server running
- environment updater running
- shared-directory watcher running

### Policy enforcement test

Test setup:

- user AVP: `dept = engineering`
- object AVP: `type = private`
- user: `alice`
- protected file: `/home/secured/test.txt`
- policy rule: `dept=engineering | type=private | * | READ`

Observed result:

- `alice` could `cat /home/secured/test.txt`
- `alice` could not append to the file
- write failed with:

```text
Operation not permitted
```

This verified that the ABAC policy path was active and enforcing.

## Files Changed

Kernel tree:

- [`linux-7.1.8-abac/security/Kconfig`](/home/ojasdubey/abac/linux-7.1.8-abac/security/Kconfig)
- [`linux-7.1.8-abac/security/Makefile`](/home/ojasdubey/abac/linux-7.1.8-abac/security/Makefile)
- [`linux-7.1.8-abac/security/abac/abac.c`](/home/ojasdubey/abac/linux-7.1.8-abac/security/abac/abac.c)
- [`linux-7.1.8-abac/security/abac/abacfs.c`](/home/ojasdubey/abac/linux-7.1.8-abac/security/abac/abacfs.c)
- [`linux-7.1.8-abac/security/abac/obj.c`](/home/ojasdubey/abac/linux-7.1.8-abac/security/abac/obj.c)

Userspace:

- [`abac_utils/setup.py`](/home/ojasdubey/abac/abac_utils/setup.py)
- [`abac_utils/install.sh`](/home/ojasdubey/abac/abac_utils/install.sh)
- [`abac_utils/src/obj.py`](/home/ojasdubey/abac/abac_utils/src/obj.py)
- [`abac_utils/src/server.py`](/home/ojasdubey/abac/abac_utils/src/server.py)

## Notes

- The original `5.10.62` source tree and tarball were removed from the workspace after the modern-kernel path was working.
- The dead `5.10.62` GRUB entry was later removed.
- The stock Fedora kernel entries were kept as fallback boot options.
