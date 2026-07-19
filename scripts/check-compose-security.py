#!/usr/bin/env python3
"""Mechanically verify the production Compose isolation contract."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

DEFAULT_IMAGE_REPOSITORY = "ghcr.io/oshinop/kfadapter"
REPOSITORY_RE = re.compile(
    r"^(?:[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*(?::[0-9]+)?(?:/[a-z0-9][a-z0-9._-]*)+)$"
)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SENSITIVE_ENV_RE = re.compile(
    r"(?:password|secret|token|credential|authkey|encryptkey|provider)", re.IGNORECASE
)


def fail(message: str) -> None:
    raise AssertionError(message)


def get(mapping: dict[str, Any], key: str) -> Any:
    if key not in mapping:
        fail(f"missing {key}")
    return mapping[key]


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(str(value))


def mount_by_target(service: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mounts: dict[str, dict[str, Any]] = {}
    for mount in service.get("volumes", []):
        if not isinstance(mount, dict):
            fail("all rendered Compose mounts must be mappings")
        target = mount.get("target")
        if not isinstance(target, str):
            fail("mount has no target")
        mounts[target] = mount
    return mounts


def assert_loopback_ports(service: dict[str, Any]) -> None:
    ports = service.get("ports")
    if not isinstance(ports, list) or len(ports) != 2:
        fail("kfadapter must publish exactly two loopback ports")
    expected = {10809, 10808}
    actual: set[int] = set()
    for port in ports:
        if not isinstance(port, dict):
            fail("published ports must use structured Compose mappings")
        host_ip = port.get("host_ip", port.get("hostIp"))
        if host_ip != "127.0.0.1":
            fail("published ports must bind only to 127.0.0.1")
        if port.get("protocol", "tcp") != "tcp":
            fail("published ports must use TCP")
        target = as_int(get(port, "target"))
        published = as_int(get(port, "published"))
        if target != published or target not in expected:
            fail("published ports must map only matching adapter listener ports")
        actual.add(target)
    if actual != expected:
        fail("kfadapter must publish web and SOCKS listener ports exactly once")


def assert_kfadapter(service: dict[str, Any]) -> None:
    if "network_mode" in service:
        fail("kfadapter must use Compose bridge networking")
    assert_loopback_ports(service)
    if service.get("user") != "65532:65532":
        fail("kfadapter must use numeric user 65532:65532")
    if service.get("working_dir") != "/kfadapter":
        fail("kfadapter working directory must be /kfadapter")
    if service.get("privileged"):
        fail("kfadapter must never be privileged")
    if service.get("pid") == "host":
        fail("kfadapter must not use the host PID namespace")
    if service.get("read_only") is not True:
        fail("kfadapter root filesystem must be read-only")
    if service.get("restart") != "unless-stopped":
        fail("kfadapter restart policy must be unless-stopped")
    if service.get("stop_grace_period") != "30s":
        fail("kfadapter stop grace period must be 30s")
    if set(service.get("cap_drop", [])) != {"ALL"}:
        fail("kfadapter must drop all capabilities")
    if "no-new-privileges:true" not in service.get("security_opt", []):
        fail("kfadapter must enable no-new-privileges")
    if as_int(get(service, "pids_limit")) != 128:
        fail("kfadapter PID limit must be 128")
    if str(get(service, "mem_limit")).lower() not in {"256m", "268435456"}:
        fail("kfadapter memory limit must be 256m")
    if float(get(service, "cpus")) != 1.0:
        fail("kfadapter CPU limit must be 1.0")

    nofile = get(get(service, "ulimits"), "nofile")
    if as_int(get(nofile, "soft")) != 65536 or as_int(get(nofile, "hard")) != 65536:
        fail("kfadapter nofile limits must be 65536")

    environment = get(service, "environment")
    if set(environment) != {"TZ"}:
        fail("kfadapter environment must contain only TZ")
    for name, value in environment.items():
        if SENSITIVE_ENV_RE.search(name) or SENSITIVE_ENV_RE.search(str(value)):
            fail(f"secret-like Compose environment entry: {name}")

    mounts = mount_by_target(service)
    if set(mounts) != {"/kfadapter/data", "/kfadapter/config.yml"}:
        fail("kfadapter may mount only state and its configuration")
    state = mounts["/kfadapter/data"]
    config = mounts["/kfadapter/config.yml"]
    if state.get("type") != "volume" or state.get("read_only") is True:
        fail("state must be the sole writable named-volume mount")
    if str(get(state, "source")) != "db_data":
        fail("state mount must use the production db_data volume declaration")
    if config.get("type") != "bind" or config.get("read_only") is not True:
        fail("configuration must be a read-only bind mount")

    tmpfs = service.get("tmpfs", [])
    if tmpfs != ["/tmp:rw,noexec,nosuid,nodev,size=16m"]:
        fail("kfadapter must have the exact bounded hardened /tmp tmpfs")

    healthcheck = get(service, "healthcheck")
    expected_healthcheck = ["CMD", "./kfadapter", "healthcheck"]
    if healthcheck.get("test") != expected_healthcheck:
        fail("healthcheck must use the adapter's default configuration")
    for key, expected in {"interval": "30s", "timeout": "5s", "retries": 3, "start_period": "10s"}.items():
        if healthcheck.get(key) != expected:
            fail(f"healthcheck {key} must be {expected}")

    logging = get(service, "logging")
    if logging.get("driver") != "local":
        fail("kfadapter logging driver must be local")
    if logging.get("options") != {"max-size": "10m", "max-file": "3"}:
        fail("kfadapter log bounds must be 10m x 3")



def assert_managed_state_volume(config: dict[str, Any], expected_name: str) -> None:
    volumes = get(config, "volumes")
    if set(volumes) != {"db_data"}:
        fail("Compose must declare only the db_data state volume")
    state_volume = get(volumes, "db_data")
    if set(state_volume) != {"name"} or state_volume["name"] != expected_name:
        fail(f"db_data must be a bare Compose-managed volume resolving to {expected_name}")


def render_compose(root: Path, env: dict[str, str], project_name: str | None = None) -> dict[str, Any]:
    command = ["docker", "compose", "--env-file", "/dev/null"]
    if project_name is not None:
        command.extend(["--project-name", project_name])
    command.extend(["-f", str(root / "compose.yaml"), "config", "--format", "json"])
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True)
    if result.returncode:
        sys.stderr.write(result.stderr)
        fail("docker compose config failed")
    return json.loads(result.stdout)


def assert_combined_image_rejected(root: Path, digest: str) -> dict[str, Any]:
    env = os.environ.copy()
    env.pop("KFADAPTER_IMAGE_REPOSITORY", None)
    env["KFADAPTER_IMAGE_DIGEST"] = digest
    env["KFADAPTER_IMAGE"] = "attacker.invalid/kfadapter:latest"
    config = render_compose(root, env)
    service = get(get(config, "services"), "kfadapter")
    image = str(get(service, "image"))
    expected_image = f"{DEFAULT_IMAGE_REPOSITORY}@{digest}"
    if image != expected_image:
        fail("Compose accepted a combined or tag-only KFADAPTER_IMAGE value")
    return config

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-repository", required=True)
    parser.add_argument("--image-digest", required=True)
    args = parser.parse_args()
    if not REPOSITORY_RE.fullmatch(args.image_repository):
        parser.error("--image-repository must be an untagged registry repository")
    if not DIGEST_RE.fullmatch(args.image_digest):
        parser.error("--image-digest must be sha256:<64 lowercase hex>")

    root = Path(__file__).resolve().parents[1]
    default_config = assert_combined_image_rejected(root, args.image_digest)
    default_services = get(default_config, "services")
    assert_kfadapter(get(default_services, "kfadapter"))
    assert_managed_state_volume(default_config, "kfadapter_db_data")

    env = os.environ.copy()
    env["KFADAPTER_IMAGE_REPOSITORY"] = args.image_repository
    env["KFADAPTER_IMAGE_DIGEST"] = args.image_digest
    config = render_compose(root, env)
    services = get(config, "services")
    assert_kfadapter(get(services, "kfadapter"))
    assert_managed_state_volume(config, "kfadapter_db_data")
    project_override = "kfadapter-volume-contract"
    override_config = render_compose(root, env, project_override)
    assert_managed_state_volume(override_config, f"{project_override}_db_data")
    image = str(get(services["kfadapter"], "image"))
    expected_image = f"{args.image_repository}@{args.image_digest}"
    if image != expected_image or not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image):
        fail("kfadapter image must be the supplied immutable repository and digest")
    print("compose-security: passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"compose-security: {error}", file=sys.stderr)
        raise SystemExit(1)
