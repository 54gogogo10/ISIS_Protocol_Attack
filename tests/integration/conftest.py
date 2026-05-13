import pytest
import subprocess
import time
import os
import json
import re
import tempfile

COMPOSE_FILE = "docker/topo1-single-area/docker-compose.yml"
R1 = "isis_r1"
R2 = "isis_r2"
ATTACKER = "isis_attacker"


def docker_exec(container: str, cmd: list[str], timeout: int = 15) -> str:
    result = subprocess.run(
        ["docker", "exec", container] + cmd,
        capture_output=True, text=True, timeout=timeout,
    )
    return result.stdout


def frr_vtysh(container: str, command: str, timeout: int = 15) -> str:
    return docker_exec(container, ["vtysh", "-c", command], timeout)


# ---------------------------------------------------------------------------
# ISIS state parsers
# ---------------------------------------------------------------------------

def get_isis_neighbors(container: str) -> list:
    """Parse 'show isis neighbor json' into a flat list of adjacency entries."""
    out = frr_vtysh(container, "show isis neighbor json")
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    adj_list = []
    areas = data.get("areas", [])
    if isinstance(areas, list):
        for area_entry in areas:
            circuits = area_entry.get("circuits", [])
            for circ in circuits:
                adj_list.append(circ)
    return adj_list


def get_isis_database(container: str) -> dict:
    """Parse 'show isis database detail json' output."""
    out = frr_vtysh(container, "show isis database detail json")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {}


def get_ip_routes(container: str) -> dict:
    """Parse 'show ip route json' output."""
    out = frr_vtysh(container, "show ip route json")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {}


def get_isis_db_count(container: str) -> int:
    """Count LSP entries (non-empty lsp keys) in the ISIS database."""
    db = get_isis_database(container)
    total = 0
    areas = db.get("areas", [])
    if isinstance(areas, list):
        for area_entry in areas:
            levels = area_entry.get("levels", [])
            for lvl in levels:
                lsp = lvl.get("lsp", {})
                if lsp and lsp.get("id"):
                    total += 1
    return total


# ---------------------------------------------------------------------------
# Convergence / wait helpers
# ---------------------------------------------------------------------------

def wait_for_isis_convergence(container: str, expected_neighbors: int = 1,
                              timeout: int = 45) -> bool:
    """Wait until ISIS adjacency is Up."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        nbrs = get_isis_neighbors(container)
        up_count = sum(1 for n in nbrs if n.get("state") == "Up")
        if up_count >= expected_neighbors:
            return True
        time.sleep(2)
    return False


def get_routes_on(container: str, prefix: str = "172.31.0") -> list:
    """Get routes matching prefix from container."""
    routes = get_ip_routes(container)
    matched = []
    for pfx, info in routes.items():
        if prefix in pfx:
            matched.append(info)
    return matched


# ---------------------------------------------------------------------------
# Topology fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def docker_network():
    """Start ISIS test topology, wait for convergence, tear down after."""
    project_dir = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    compose_path = os.path.join(project_dir, COMPOSE_FILE)

    # Clean up any existing containers first, then start
    subprocess.run(
        ["docker", "compose", "-f", compose_path, "down", "-v"],
        cwd=project_dir, capture_output=True,
    )
    subprocess.run(
        ["docker", "compose", "-f", compose_path, "up", "-d", "--build"],
        check=True, cwd=project_dir, capture_output=True,
    )
    time.sleep(20)

    # Wait for ISIS convergence
    for container in [R1, R2]:
        if not wait_for_isis_convergence(container, expected_neighbors=1, timeout=60):
            pytest.fail(f"ISIS did not converge on {container}")

    yield {"r1": R1, "r2": R2, "attacker": ATTACKER}

    subprocess.run(
        ["docker", "compose", "-f", compose_path, "down", "-v"],
        check=True, cwd=project_dir, capture_output=True,
    )


# ---------------------------------------------------------------------------
# Attack helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def attacker(docker_network):
    """Verify attacker container and isis_attack import."""
    result = docker_exec(ATTACKER, ["python", "-c", "import isis_attack; print('OK')"])
    assert "OK" in result
    return ATTACKER


def run_attack_in_container(attack_cmd: list[str], timeout: int = 30) -> str:
    """Run isis-attack command inside attacker container."""
    cmd = ["python", "-m", "isis_attack.cli.main"] + attack_cmd
    result = subprocess.run(
        ["docker", "exec", ATTACKER] + cmd,
        capture_output=True, timeout=timeout,
    )
    return (result.stdout or b"").decode("utf-8", errors="replace")


def run_attack_script(script: str, timeout: int = 30) -> str:
    """Write and execute a Python script in the attacker container."""
    fd, host_path = tempfile.mkstemp(suffix=".py", prefix="isis_test_")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(script)

    container_path = "/tmp/isis_test_script.py"
    subprocess.run(
        ["docker", "cp", host_path, f"{ATTACKER}:{container_path}"],
        check=True, capture_output=True,
    )

    result = subprocess.run(
        ["docker", "exec", ATTACKER, "python", container_path],
        capture_output=True, timeout=timeout,
    )
    os.unlink(host_path)
    return (result.stdout or b"").decode("utf-8", errors="replace")
