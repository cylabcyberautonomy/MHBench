from __future__ import annotations

import hashlib
import logging
import os
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import ansible_runner
from openstack.connection import Connection

from config.config import Config
from src.abstractions.network import NetworkTopology
from src.deployment.online_registry_service import OnlineRegistryService
from src.playbooks.playbook_registry_service import PlaybookRegistryService

logger = logging.getLogger(__name__)

_MHBENCH_DIR = Path(__file__).resolve().parent.parent.parent
_CONSOLE_TAIL_LINES = 100
_PLAYBOOK_RETRIES = 5
_PLAYBOOK_RETRY_DELAY = 20
_PARALLEL_HOSTS = 8  # max hosts configured concurrently in run_parallel (bounds the single bastion's sshd load)
_COLLECT_RETRIES = 5       # in-place collect retries (VMs still up); only re-fetches hosts that came back empty
_COLLECT_RETRY_DELAY = 30  # backoff between collect retries — lets a saturated bastion recover


class AnsibleRunner:

    def __init__(
        self,
        config: Config,
        online_registry: OnlineRegistryService,
        playbook_registry: PlaybookRegistryService,
        conn: Connection | None = None,
        project_name: str | None = None,
    ) -> None:
        self._ssh_key_path = config.openstack.ssh_key_path
        self._online = online_registry
        self._playbook_registry = playbook_registry
        self._conn = conn
        self._project_name = project_name
        c2c = getattr(config, "c2c", None)
        self._c2c_vars: dict = {"caldera_ip": c2c.ip, "caldera_port": c2c.port} if c2c else {}
        self._attacker_play = getattr(config, "attacker_play", None)  # overrides the kali host's runtime play (per-attacker)
        self._attacker_only = getattr(config, "attacker_only", False)  # run ONLY the kali attacker host's play (post-config setup step)
        self._verbosity = getattr(config, "ansible_verbosity", 0)

    def _ssh_ctl_dir(self) -> str:
        """Per-experiment SSH ControlPath directory, namespaced by project (see the callers'
        own comments on why: isolating concurrent runs that reuse the same internal IPs).
        Hashed rather than the raw project name: AF_UNIX socket paths cap out at 108 bytes,
        and OpenSSH appends its own ~17-byte suffix (". " + 16 random chars) when atomically
        creating the control socket on top of the 40-char %C hash / "bastion-<ip>" filename -
        so a project name longer than about two dozen characters can silently break every SSH
        connection for that experiment ("ControlPath too long" / "too long for Unix domain
        socket"). A short fixed-length hash keeps this well under the limit regardless of how
        the experiment is named."""
        if not self._project_name:
            return "/tmp/mhbench-ssh/default"
        digest = hashlib.sha1(self._project_name.encode()).hexdigest()[:10]
        return f"/tmp/mhbench-ssh/{digest}"

    def _log_console(self, host_name: str) -> None:
        if not self._conn:
            return
        full_name = f"{self._project_name}-{host_name}" if self._project_name else host_name
        server = self._conn.compute.find_server(full_name)
        if not server:
            logger.warning("Could not find server '%s' to fetch console log", full_name)
            return
        try:
            output = self._conn.compute.get_server_console_output(server.id, length=_CONSOLE_TAIL_LINES)
            console_text = output.get("output", "") if isinstance(output, dict) else str(output)
            logger.info("Console log for %s (last %d lines):\n%s", full_name, _CONSOLE_TAIL_LINES, console_text)
        except Exception:
            logger.exception("Failed to fetch console log for '%s'", full_name)

    def _run_playbook(self, pb_name: str, inventory: dict, extravars: dict, tmp: str, project_dir: str,
                      log_path: str | None = None) -> None:
        pb_path = self._playbook_registry.get_path(pb_name)
        # Per-experiment ControlPath dir. %C hashes only (host,port,user) — NOT the bastion — so concurrent
        # experiments (identical internal IPs 192.168.200.x reached via different bastions) would otherwise
        # share one mux socket and configure each other's hosts. Namespacing by project isolates runs while
        # keeping the intra-run per-host connection reuse.
        ssh_ctl_dir = self._ssh_ctl_dir()
        Path(ssh_ctl_dir).mkdir(parents=True, exist_ok=True)
        logf = open(log_path, "a") if log_path else None  # route this play's ansible trace to a per-host file, off shared stdout
        def _stream(event: dict) -> bool:
            line = event.get("stdout", "")
            if line:
                logf.write(line) if logf else print(line, end="", flush=True)
            return True

        try:
            for attempt in range(1, _PLAYBOOK_RETRIES + 1):
                result = ansible_runner.run(
                    private_data_dir=tmp,
                    project_dir=project_dir,
                    playbook=pb_path.name,
                    inventory=inventory,
                    extravars=extravars,
                    event_handler=_stream,
                    quiet=True,
                    verbosity=self._verbosity,
                    envvars={
                        # One reused SSH connection per host across all tasks (ControlPersist) instead of a fresh
                        # handshake per task — a 26-host configure otherwise opens thousands of connections through
                        # the single bastion and overwhelms its sshd (the kex/timeout/connection-closed storms).
                        "ANSIBLE_SSH_ARGS": (
                            "-o ControlMaster=auto "
                            f"-o ControlPath={ssh_ctl_dir}/%C "
                            "-o ControlPersist=60s "
                            "-o StrictHostKeyChecking=no "
                            "-o UserKnownHostsFile=/dev/null "
                            "-o ServerAliveInterval=30 "
                            "-o ServerAliveCountMax=10"
                        ),
                        "ANSIBLE_PIPELINING": "True",
                        "ANSIBLE_SSH_RETRIES": "3",
                    }
                )
                if result.status == "successful":
                    return
                stderr = result.stderr.read() if result.stderr else ""
                if attempt < _PLAYBOOK_RETRIES:
                    logger.warning(
                        "Playbook '%s' failed (attempt %d/%d, status: %s) — retrying in %ds.\n%s",
                        pb_name, attempt, _PLAYBOOK_RETRIES, result.status, _PLAYBOOK_RETRY_DELAY, stderr,
                    )
                    time.sleep(_PLAYBOOK_RETRY_DELAY)
                else:
                    raise RuntimeError(
                        f"Playbook '{pb_name}' failed after {_PLAYBOOK_RETRIES} attempts (status: {result.status}).\n{stderr}"
                    )
        finally:
            if logf:
                logf.close()

    def run(self, topology: NetworkTopology, mgmt_floating_ip: str) -> None:
        hosts = topology.get_all_hosts()
        for host in hosts:
            if host.ip_address is None:
                raise RuntimeError(f"Host '{host.name}' has no ip_address; cannot build ansible inventory.")

        # bastion-hop mux: all hosts share ONE ssh connection to the bastion (separate -W channels) so the
        # parallel-configure burst can't trip its default MaxStartups (10) and drop the attacker. Per-experiment
        # socket keyed on the bastion IP + namespaced per-project (same dir as the outer per-target mux) so
        # concurrent runs — same internal IPs, different bastions — never share a socket.
        ctl = self._ssh_ctl_dir()
        proxy = (
            f"ssh -W %h:%p -i {self._ssh_key_path} "
            f"-o BatchMode=yes -o PasswordAuthentication=no "  # fail fast if bastion key-auth fails -> no password-prompt hang
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ControlMaster=auto -o ControlPath={ctl}/bastion-{mgmt_floating_ip} -o ControlPersist=300s "
            f"root@{mgmt_floating_ip}"
        )
        inventory_hosts = {
            host.name: {
                "ansible_host": str(host.ip_address),
                "ansible_port": 22,
                "ansible_user": "root",
                "ansible_ssh_private_key_file": self._ssh_key_path,
                "ansible_ssh_common_args": (
                    f'-o StrictHostKeyChecking=no '
                    f'-o UserKnownHostsFile=/dev/null '
                    f'-o ServerAliveInterval=30 '
                    f'-o ServerAliveCountMax=10 '
                    f'-o ProxyCommand="{proxy}"'
                ),
            }
            for host in hosts
        }

        queue: list[tuple[str | None, str, dict]] = []
        for host in hosts:
            if self._attacker_only and host.vm_type != "kali_running":
                continue
            runtime_pbs = self._online.get_runtime_playbooks(host.vm_type)
            if self._attacker_play and host.vm_type == "kali_running":
                runtime_pbs = [self._attacker_play]
            if runtime_pbs:
                queue.append((host.name, "check_if_host_up", {
                    "manage_ip": mgmt_floating_ip,
                    "ssh_key_path": self._ssh_key_path,
                }))
                for pb_name in runtime_pbs:
                    queue.append((host.name, pb_name, {"user": "root", **self._c2c_vars}))
        if not self._attacker_only:
            for pb in topology.playbooks:
                queue.append((None, pb.name, pb.args))

        if not queue:
            logger.info("No playbooks to run.")
            return

        first_pb = self._playbook_registry.get_path(queue[0][1])
        project_dir = str((_MHBENCH_DIR / first_pb).resolve().parent)

        with tempfile.TemporaryDirectory() as tmp:
            for host_name, pb_name, args in queue:
                extravars = {"host": host_name, **args} if host_name else args
                if host_name:
                    logger.info("Running playbook '%s' on '%s'", pb_name, host_name)
                else:
                    logger.info("Running topology playbook '%s'", pb_name)
                try:
                    self._run_playbook(
                        pb_name,
                        {"all": {"hosts": inventory_hosts}},
                        extravars,
                        tmp,
                        project_dir,
                    )
                except RuntimeError:
                    if host_name:
                        self._log_console(host_name)
                    raise

    def run_parallel(self, topology: NetworkTopology, mgmt_floating_ip: str) -> None:
        # Same result as run(), but the per-host online plays (no cross-host deps) run concurrently in a
        # bounded thread pool, then the topology plays (setup_ssh_keys/add_data — cross-host) run serially
        # after. Capped at _PARALLEL_HOSTS so the single bastion's sshd isn't swamped (each host reuses one
        # mux connection). Inventory + chain setup mirrors run(); kept separate so run() stays the safe serial path.
        hosts = topology.get_all_hosts()
        for host in hosts:
            if host.ip_address is None:
                raise RuntimeError(f"Host '{host.name}' has no ip_address; cannot build ansible inventory.")

        # bastion-hop mux: all hosts share ONE ssh connection to the bastion (separate -W channels) so the
        # parallel-configure burst can't trip its default MaxStartups (10) and drop the attacker. Per-experiment
        # socket keyed on the bastion IP + namespaced per-project (same dir as the outer per-target mux) so
        # concurrent runs — same internal IPs, different bastions — never share a socket.
        ctl = self._ssh_ctl_dir()
        proxy = (
            f"ssh -W %h:%p -i {self._ssh_key_path} "
            f"-o BatchMode=yes -o PasswordAuthentication=no "  # fail fast if bastion key-auth fails -> no password-prompt hang
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ControlMaster=auto -o ControlPath={ctl}/bastion-{mgmt_floating_ip} -o ControlPersist=300s "
            f"root@{mgmt_floating_ip}"
        )
        inventory_hosts = {
            host.name: {
                "ansible_host": str(host.ip_address),
                "ansible_port": 22,
                "ansible_user": "root",
                "ansible_ssh_private_key_file": self._ssh_key_path,
                "ansible_ssh_common_args": (
                    f'-o StrictHostKeyChecking=no '
                    f'-o UserKnownHostsFile=/dev/null '
                    f'-o ServerAliveInterval=30 '
                    f'-o ServerAliveCountMax=10 '
                    f'-o ProxyCommand="{proxy}"'
                ),
            }
            for host in hosts
        }

        # Per-host chain = check_if_host_up then that host's online plays, ordered (a host's own plays are
        # sequential; only across hosts is it parallel). Topology plays are cross-host and run after, serially.
        per_host: dict[str, list[tuple[str, dict]]] = {}
        for host in hosts:
            if self._attacker_only and host.vm_type != "kali_running":
                continue
            runtime_pbs = self._online.get_runtime_playbooks(host.vm_type)
            if self._attacker_play and host.vm_type == "kali_running":
                runtime_pbs = [self._attacker_play]
            if runtime_pbs:
                per_host[host.name] = (
                    [("check_if_host_up", {"manage_ip": mgmt_floating_ip, "ssh_key_path": self._ssh_key_path})]
                    + [(pb_name, {"user": "root", **self._c2c_vars}) for pb_name in runtime_pbs]
                )
        topo = [] if self._attacker_only else [(pb.name, pb.args) for pb in topology.playbooks]

        if not per_host and not topo:
            logger.info("No playbooks to run.")
            return

        first_name = next(iter(per_host.values()))[0][0] if per_host else topo[0][0]
        project_dir = str((_MHBENCH_DIR / self._playbook_registry.get_path(first_name)).resolve().parent)
        logger.info("Parallel configure: %d hosts (max %d concurrent) + %d topology plays",
                    len(per_host), _PARALLEL_HOSTS, len(topo))

        ansible_log_dir = os.environ.get("MHBENCH_ANSIBLE_LOG_DIR")  # harness points per-host ansible logs here; None -> stdout
        if ansible_log_dir:
            Path(ansible_log_dir).mkdir(parents=True, exist_ok=True)

        # Pre-establish the ONE bastion ControlMaster BEFORE fanning out, so the parallel plays REUSE it instead of
        # racing to create it. Without this, ControlMaster=auto + N concurrent procs race: the losers hit "ControlSocket
        # already exists, disabling multiplexing" -> a non-mux fallback that dies as "Connection closed by UNKNOWN port
        # 65535" -> host UNREACHABLE -> setup_ssh_keys fails (verified by reproduction). An ad-hoc connect to the bastion
        # opens the master at the same ControlPath the ProxyCommand targets. Best-effort: on failure the plays fall back
        # to the old on-demand behavior, so this can only help.
        Path(ctl).mkdir(parents=True, exist_ok=True)
        # Raise the bastion's MaxStartups (stock 10:30:100 throttles the parallel plays' connection burst -> the
        # setup_ssh_keys "port 65535" drops) + reload sshd, before the master opens below.
        with tempfile.TemporaryDirectory() as ms_tmp:
            ansible_runner.run(
                private_data_dir=ms_tmp, host_pattern="bastion", module="raw",
                module_args=(
                    "sed -i '/^[[:space:]]*MaxStartups/d' /etc/ssh/sshd_config && "
                    "printf 'MaxStartups 200:30:400\\n' >> /etc/ssh/sshd_config && "
                    "(systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload)"
                ),
                quiet=True, verbosity=self._verbosity,
                inventory={"all": {"hosts": {"bastion": {
                    "ansible_host": mgmt_floating_ip, "ansible_user": "root",
                    "ansible_ssh_private_key_file": self._ssh_key_path,
                    "ansible_ssh_common_args": "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
                }}}},
            )
        with tempfile.TemporaryDirectory() as warm_tmp:
            warm = ansible_runner.run(
                private_data_dir=warm_tmp, host_pattern="bastion", module="raw", module_args="true", quiet=True,
                verbosity=self._verbosity,
                inventory={"all": {"hosts": {"bastion": {
                    "ansible_host": mgmt_floating_ip, "ansible_user": "root",
                    "ansible_ssh_private_key_file": self._ssh_key_path,
                    "ansible_ssh_common_args": (
                        f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                        f"-o ControlMaster=auto -o ControlPath={ctl}/bastion-{mgmt_floating_ip} -o ControlPersist=300s"
                    ),
                }}}},
            )
        if warm.status == "successful":
            logger.info("Bastion ControlMaster pre-warmed at %s", mgmt_floating_ip)
        else:
            logger.warning("Bastion ControlMaster pre-warm did not succeed (status=%s); falling back to on-demand.",
                           warm.status)

        def _run_host_chain(host_name: str, chain: list[tuple[str, dict]]) -> None:
            log_path = f"{ansible_log_dir}/{host_name}.log" if ansible_log_dir else None
            with tempfile.TemporaryDirectory() as tmp:  # own private_data_dir per thread — a shared one clobbers
                for pb_name, args in chain:
                    logger.info("Running playbook '%s' on '%s'", pb_name, host_name)
                    self._run_playbook(pb_name, {"all": {"hosts": inventory_hosts}},
                                       {"host": host_name, **args}, tmp, project_dir, log_path)

        # Phase 1: per-host online plays, up to _PARALLEL_HOSTS at once. Wait for all, then surface failures.
        with ThreadPoolExecutor(max_workers=_PARALLEL_HOSTS) as pool:
            futures = {pool.submit(_run_host_chain, h, chain): h for h, chain in per_host.items()}
            errors = []
            for fut in as_completed(futures):
                exc = fut.exception()
                if exc:
                    errors.append((futures[fut], exc))
        if errors:
            for host_name, _ in errors:
                self._log_console(host_name)  # serial after the pool — avoids concurrent use of self._conn
            raise RuntimeError(
                f"Parallel configure failed on {len(errors)} host(s): "
                + "; ".join(f"{h}: {e}" for h, e in errors[:5])
            )

        # Phase 2: topology plays, run in the same bounded pool as phase 1 but guarded by a per-host lock so plays
        # touching the same host serialize — setup_ssh_keys all write the 'attacker' leader's ~/.ssh/config (must
        # serialize), while the many add_data plays hit disjoint hosts and run fully concurrent (the bulk of the win).
        if topo:
            # A play touches whatever hosts its args name: host + follower (legacy single pair) + followers[]
            # (a play may fan a leader out to many followers). Generic — no per-playbook knowledge here.
            def _touched(args: dict) -> set:
                return ({args.get("host"), args.get("follower")}
                        | {f["follower"] for f in args.get("followers", [])}) - {None}

            all_hosts: set[str] = set()
            for _, args in topo:
                all_hosts |= _touched(args)
            host_locks = {h: threading.Lock() for h in all_hosts}

            def _run_topo(idx: int, pb_name: str, args: dict) -> None:
                held = [host_locks[h] for h in sorted(_touched(args))]
                for lk in held:  # sorted acquire order across all plays ⇒ no deadlock
                    lk.acquire()
                try:
                    log_path = f"{ansible_log_dir}/_topology_{idx}_{pb_name}.log" if ansible_log_dir else None
                    with tempfile.TemporaryDirectory() as tmp:  # own private_data_dir per thread — a shared one clobbers
                        logger.info("Running topology playbook '%s'", pb_name)
                        self._run_playbook(pb_name, {"all": {"hosts": inventory_hosts}}, args, tmp, project_dir, log_path)
                finally:
                    for lk in reversed(held):
                        lk.release()

            with ThreadPoolExecutor(max_workers=_PARALLEL_HOSTS) as pool:
                futures = {pool.submit(_run_topo, i, pb, args): pb for i, (pb, args) in enumerate(topo)}
                errors = []
                for fut in as_completed(futures):
                    exc = fut.exception()
                    if exc:
                        errors.append((futures[fut], exc))
            if errors:
                raise RuntimeError(
                    f"Topology configure failed on {len(errors)} play(s): "
                    + "; ".join(f"{p}: {e}" for p, e in errors[:5])
                )

    def collect(self, topology: NetworkTopology, mgmt_floating_ip: str, dest: str) -> None:
        # Post-experiment log exfil: rebuild the same bastion ProxyJump inventory as run() and
        # fetch every host's ground-truth logs to <dest>/<host>/. One play over all hosts (ansible
        # forks parallelize the fetch); ignore_unreachable in the play keeps a dead host from
        # sinking the rest. Runs before teardown deletes the VMs.
        logger.debug("Collecting host logs to %s via mgmt %s", dest, mgmt_floating_ip)
        # every host including the attacker (kali) — its image now bakes in the same telemetry
        hosts = list(topology.get_all_hosts())
        for host in hosts:
            if host.ip_address is None:
                raise RuntimeError(f"Host '{host.name}' has no ip_address; cannot build ansible inventory.")
            # ansible.builtin.copy (the auditctl-dump task) does NOT create its destination
            # directory the way ansible.builtin.fetch does further down in the same play — on any
            # host where auditctl actually succeeds (rc == 0, so that task's `when` is true rather
            # than cleanly skipping) it fails outright with "Destination directory ... does not
            # exist", since nothing else in this call chain ever creates <dest>/<host>/.
            Path(dest, host.name).mkdir(parents=True, exist_ok=True)

        # bastion-hop mux: all hosts share ONE ssh connection to the bastion (separate -W channels) so the
        # parallel-configure burst can't trip its default MaxStartups (10) and drop the attacker. Per-experiment
        # socket keyed on the bastion IP + namespaced per-project (same dir as the outer per-target mux) so
        # concurrent runs — same internal IPs, different bastions — never share a socket.
        ctl = self._ssh_ctl_dir()
        proxy = (
            f"ssh -W %h:%p -i {self._ssh_key_path} "
            f"-o BatchMode=yes -o PasswordAuthentication=no "  # fail fast if bastion key-auth fails -> no password-prompt hang
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ControlMaster=auto -o ControlPath={ctl}/bastion-{mgmt_floating_ip} -o ControlPersist=300s "
            f"root@{mgmt_floating_ip}"
        )
        inventory_hosts = {
            host.name: {
                "ansible_host": str(host.ip_address),
                "ansible_port": 22,
                "ansible_user": "root",
                "ansible_ssh_private_key_file": self._ssh_key_path,
                "ansible_ssh_common_args": (
                    f'-o StrictHostKeyChecking=no '
                    f'-o UserKnownHostsFile=/dev/null '
                    f'-o ServerAliveInterval=30 '
                    f'-o ServerAliveCountMax=10 '
                    f'-o ProxyCommand="{proxy}"'
                ),
            }
            for host in hosts
        }

        pb_path = self._playbook_registry.get_path("collect_host_logs")
        project_dir = str((_MHBENCH_DIR / pb_path).resolve().parent)
        # Retry collection IN PLACE (VMs are still up), each pass re-fetching ONLY the hosts whose
        # <dest>/<host>/ is still empty — a host that already returned its logs is never re-copied, and a
        # transient bastion drop no longer costs the whole experiment a re-attack. Best-effort: after the
        # retries, proceed to teardown with a loud warning for any host that never returned logs, instead of
        # raising (which would escalate to a full-experiment retry).
        pending = dict(inventory_hosts)
        for attempt in range(1, _COLLECT_RETRIES + 1):
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    self._run_playbook("collect_host_logs", {"all": {"hosts": pending}}, {"dest": dest}, tmp, project_dir)
                except Exception as e:
                    logger.warning("collect_host_logs attempt %d/%d had failures — retrying incomplete hosts.\n%s",
                                   attempt, _COLLECT_RETRIES, e)
            pending = {n: h for n, h in inventory_hosts.items()
                       if not (Path(dest) / n).is_dir() or not any((Path(dest) / n).iterdir())}
            if not pending:
                return
            if attempt < _COLLECT_RETRIES:
                time.sleep(_COLLECT_RETRY_DELAY)
        logger.warning("collect_host_logs: %d host(s) returned no logs after %d attempts (proceeding best-effort): %s",
                       len(pending), _COLLECT_RETRIES, sorted(pending))

    def rotate_logs(self, topology: NetworkTopology, mgmt_floating_ip: str) -> None:
        # Pre-attack reset: rebuild the same bastion ProxyJump inventory as collect() and reset every
        # host's ground-truth logs to empty at the deploy->attack boundary, so post-experiment
        # collection yields attack-phase-only logs. The harness blocks the attacker on this. Includes
        # the attacker (kali), same as collect() — its image now bakes in the same telemetry.
        logger.debug("Rotating host logs via mgmt %s", mgmt_floating_ip)
        hosts = list(topology.get_all_hosts())
        for host in hosts:
            if host.ip_address is None:
                raise RuntimeError(f"Host '{host.name}' has no ip_address; cannot build ansible inventory.")

        # bastion-hop mux: all hosts share ONE ssh connection to the bastion (separate -W channels) so the
        # parallel-configure burst can't trip its default MaxStartups (10) and drop the attacker. Per-experiment
        # socket keyed on the bastion IP + namespaced per-project (same dir as the outer per-target mux) so
        # concurrent runs — same internal IPs, different bastions — never share a socket.
        ctl = self._ssh_ctl_dir()
        proxy = (
            f"ssh -W %h:%p -i {self._ssh_key_path} "
            f"-o BatchMode=yes -o PasswordAuthentication=no "  # fail fast if bastion key-auth fails -> no password-prompt hang
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ControlMaster=auto -o ControlPath={ctl}/bastion-{mgmt_floating_ip} -o ControlPersist=300s "
            f"root@{mgmt_floating_ip}"
        )
        inventory_hosts = {
            host.name: {
                "ansible_host": str(host.ip_address),
                "ansible_port": 22,
                "ansible_user": "root",
                "ansible_ssh_private_key_file": self._ssh_key_path,
                "ansible_ssh_common_args": (
                    f'-o StrictHostKeyChecking=no '
                    f'-o UserKnownHostsFile=/dev/null '
                    f'-o ServerAliveInterval=30 '
                    f'-o ServerAliveCountMax=10 '
                    f'-o ProxyCommand="{proxy}"'
                ),
            }
            for host in hosts
        }

        pb_path = self._playbook_registry.get_path("rotate_host_logs")
        project_dir = str((_MHBENCH_DIR / pb_path).resolve().parent)
        with tempfile.TemporaryDirectory() as tmp:
            self._run_playbook(
                "rotate_host_logs",
                {"all": {"hosts": inventory_hosts}},
                {},
                tmp,
                project_dir,
            )
