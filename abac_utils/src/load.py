# ABAC load command for loading attributes and policy into kernel
# Copyright (C) 2021 Hariyala Omakara Naga Sai Varshith

import os
import sys
import click
import json
from pathlib import Path
from .common import check_root
from .config import *

def check_files(config_path, kernel_path):
    """
    Checks if the files at config_path and kernel_paths are available.
    """
    if not Path(config_path).is_file():
            sys.exit(f"ABAC config not initialized. {config_path} missing")
    if not Path(kernel_path).is_file():
        sys.exit(f"Kernel User attribute file {kernel_path} not found.")

def load_user_attr():
    """parse user attributes json config and load them into the kernel"""
    # check if the user attributes file is present
    config_path = CONFIG_ROOT + CONFIG_USER_ATTRS_FILE  
    kernel_path = ABAC_MOUNT + KERN_USER_ATTRS_FILE  
    check_files(config_path, kernel_path)

    with open(config_path) as f:
        users = json.load(f)["users"]
    if len(users.keys()) == 0:
        print("No user attributes found. Not writing anything...")
        return
    content = ""
    for username, data in users.items():
        avps = []
        for name, value in data['avps'].items():
            avps.append(f"{name}={value}")
        if len(avps) == 0:
            continue
        content += f"{data['uid']}:{','.join(avps)}\n"
    with open(kernel_path, 'w') as f:
        f.write(content)
    print("User attributes loaded into the kernel")

def load_obj_attr():
    """parse user attributes json config and load them into the kernel"""
    # check if the user attributes file is present
    config_path = CONFIG_ROOT + CONFIG_OBJ_ATTRS_FILE
    kernel_path = ABAC_MOUNT + KERN_OBJ_ATTRS_FILE 
    check_files(config_path, kernel_path)

    # read object attributes, parse them and write data to kernel file
    with open(config_path) as f:
        objects = json.load(f)["objects"]
    if len(objects.keys()) == 0:
        print("No object attributes found. Not writing anything...")
        return
    content = ""
    for path, avp_dict in objects.items():
        avps = []
        for name, value in avp_dict.items():
            avps.append(f"{name}={value}")
        if len(avps) == 0:
            continue
        content += f"{path}:{','.join(avps)}\n"
    with open(kernel_path, 'w') as f:
        f.write(content)
    print("Object attributes loaded into the kernel")

def load_env_attr():
    """parse environment attributes json config and load them into the kernel"""
    # check if the user attributes file is present
    config_path = CONFIG_ROOT + CONFIG_ENV_ATTRS_FILE
    kernel_path = ABAC_MOUNT + KERN_ENV_ATTRS_FILE 
    check_files(config_path, kernel_path)

    # read object attributes, parse them and write data to kernel file
    with open(config_path) as f:
        envs = json.load(f)["env"]
    if len(envs.keys()) == 0:
        print("No Environment attributes found. Not writing anything...")
        return
    content = ""
    for env, value in envs.items():
        content += f"{env}={value}\n"
    with open(kernel_path, 'w') as f:
        f.write(content)
    print("Environment attributes loaded into the kernel")


def load_path_scope():
    config_path = CONFIG_ROOT + CONFIG_PATH_SCOPE_FILE
    include_kernel_path = ABAC_MOUNT + KERN_INCLUDE_PATHS_FILE
    exclude_kernel_path = ABAC_MOUNT + KERN_EXCLUDE_PATHS_FILE
    check_files(config_path, include_kernel_path)
    check_files(config_path, exclude_kernel_path)

    with open(config_path) as f:
        scope = json.load(f)

    include_content = ""
    exclude_content = ""
    for path in scope.get("include", []):
        include_content += f"{str(Path(path).resolve())}\n"
    for path in scope.get("exclude", []):
        exclude_content += f"{str(Path(path).resolve())}\n"

    with open(include_kernel_path, 'w') as f:
        f.write(include_content)
    with open(exclude_kernel_path, 'w') as f:
        f.write(exclude_content)
    print("ABAC include/exclude paths loaded into the kernel")


def serialize_policy_section(attributes, section_type,
                             tee_enabled, tee_attributes):
    """Serialize one rule section and collect its TEE-protected AVPs."""
    kernel_avps = []

    for raw_name, value in attributes.items():
        protected = raw_name.startswith("tee:")
        name = raw_name[4:] if protected else raw_name

        if not name:
            sys.exit("TEE attribute name cannot be empty")

        if protected and tee_enabled:
            # The resolver needs the name and marker, but not the secret
            # expected value. It forwards the current actual value to SGX.
            kernel_avps.append(f"tee:{name}=__TEE_PROTECTED__")
            tee_attributes.append(f"{section_type}:{name}={value}")
        elif protected:
            # Local mode retains the expected value for normal evaluation.
            kernel_avps.append(f"tee:{name}={value}")
        else:
            kernel_avps.append(f"{name}={value}")

    return ",".join(kernel_avps)


def load_policy(tee_enabled=False):
    """Load kernel rules and generate the enclave-rule configuration."""
    config_path = CONFIG_ROOT + CONFIG_POLICY_FILE
    kernel_path = ABAC_MOUNT + KERN_POLICY_FILE
    tee_config_path = CONFIG_ROOT + CONFIG_TEE_RULES_FILE
    check_files(config_path, kernel_path)

    with open(config_path) as f:
        rules = json.load(f)["rules"]

    if len(rules) == 0:
        with open(tee_config_path, "w"):
            pass
        os.chmod(tee_config_path, 0o600)
        print("No rules found. Not writing anything...")
        return

    kernel_content = ""
    tee_content = ""

    for rule_id, rule in enumerate(rules, start=1):
        tee_attributes = []

        user_section = serialize_policy_section(
            rule["user"], "user", tee_enabled, tee_attributes)
        object_section = serialize_policy_section(
            rule["obj"], "object", tee_enabled, tee_attributes)
        environment_section = serialize_policy_section(
            rule["env"], "env", tee_enabled, tee_attributes)

        if not environment_section:
            environment_section = "*"

        effect = rule.get("effect", "ALLOW")
        kernel_content += (
            f"{user_section}|{object_section}|{environment_section}|"
            f"{rule['op']}|{effect}\n"
        )

        if tee_enabled and tee_attributes:
            tee_content += f"{rule_id}|{','.join(tee_attributes)}\n"

    with open(kernel_path, "w") as f:
        f.write(kernel_content)

    with open(tee_config_path, "w") as f:
        f.write(tee_content)
    os.chmod(tee_config_path, 0o600)

    print("ABAC policy loaded into kernel")
    if tee_enabled:
        print(f"TEE rules written to {tee_config_path}")


@click.command()
@click.option("--tee/--no-tee", default=False,
              help="Split tee: attributes for enclave evaluation")
def load(tee):
    """Load user, object attributes and ABAC Policy into the Kernel"""

    check_root()

    # check if the ABAC LSM's Security File System is initialized. If it was,
    # it is mounted at ABAC_MOUNT. If it wasn't, throw an error with some info.
    p = Path(ABAC_MOUNT)
    if not p.is_dir():
        sys.exit(f"ABAC security file system is not mounted. Please check if the ABAC LSM is loaded")

    load_policy(tee)
    load_user_attr()
    load_obj_attr()
    load_env_attr()
    load_path_scope()
