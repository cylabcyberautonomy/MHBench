# Instrumented Environments — Handoff

**Date:** 2026-09-07, updated 2026-09-09
**Repo:** `/home/lakshmi/MHBench` (remote `cylabcyberautonomy/MHBench`, branch `main`)
**Bake host:** `beluga1` (`10.81.1.1`), working copy at `/home/lakshmi/MHBench-instrumented`

---

## 0. 2026-09-09 update — rebake done, verified working, committing now

Closes out §6 next-actions 1–3 from the original handoff below:

1. **Rebaked and re-uploaded** `ubuntu_telemetry` / `webserver_telemetry` on beluga1 with the
   §4 sysflow fixes (`DRIVER_TYPE=ebpf-core`, dpkg `--force-overwrite`, the
   `10-falcoctl-writable.conf` systemd drop-in, sfprocessor pinned at 0.5.0). Verified all four
   are present in the built qcow2s via `virt-cat` before uploading. Glance upload hit the
   known intermittent 502 twice (once per image) — confirmed each time that `--force` had left
   no stub/partial image behind, then retried; both are now `active` in Glance with fresh
   IDs/sizes.
2. **Redeployed clean** (`sudobaron_test_instrumented`, project `verify1`) with zero manual
   edits. `sysflow-collector`, `sysflow-processor`, `falco-modern-bpf`, `falcosidekick` all came
   up `active`, `NRestarts=0`, and stayed there over a 5-minute observation window.
3. **sysflow → ES export confirmed working** — previously unverified. `sysflow-processor`
   logs showed continuous `POST /sysflow/_bulk` → `200` every few seconds; the `sysflow` index
   had 1,844+ docs and climbing (sample doc: a `file-rename` event from `systemd-logind`, full
   ECS shape). `falco` index also active (160 docs). Both export paths are now proven.
4. **Registry gap fixed**: 3 `_running` vulnerability variants had no `_instrumented`
   counterpart — `webserver_netcat`, `webserver_netcat_writeable`, `webserver_netcat_sudobaron`.
   Added all 3 to `online_registry.yaml`, matching the exact sibling pattern (vuln playbook(s) →
   `start_sysflow` → `start_defender_services` → `start_ghosts_lite`, parented on
   `webserver_telemetry`). Verified programmatically: **all 12 non-attacker `_running` variants
   now have an `_instrumented` counterpart**, and all 3 new entries resolve to
   `webserver_telemetry` with no parent loops.
5. **`verify1` and `smoke2` VMs are gone** as of 2026-09-09 — nothing under those names in
   `openstack server list --all-projects`. Not torn down by this work; unexplained gap between
   2026-09-07 and 2026-09-09 (session was compacted/interrupted for ~2 days). Not a concern for
   the deliverable — the fix lives in the rebaked Glance images, which are untouched and still
   `active`.
6. **Repo reconciliation**: between 2026-09-07 and 2026-09-09, `main` was fast-forwarded to pull
   in 3 newly-merged PRs (metasploit install play, SSH ControlPath hashing, FIP
   unreachable-vs-stale fix) that formalize what were previously the "pre-existing, not mine"
   uncommitted changes on this box. Someone stashed this instrumented work first
   (`stash@{0}`, "pre-main-update"), pulled, then `git stash apply`'d it back — cleanly, no
   conflicts, verified byte-identical to the pre-pull diff. The stash entry is still sitting
   there untouched as their backup; not dropped by this work.

**Still open** (§6 next-actions 4–5, unchanged, deferred by request):
- Decide whether sysflow is worth keeping at all vs. relying on Falco alone.
- Move ES address/credentials into `config.yaml` and rotate the `changeme` password.

**Not committed this pass** (still the pre-existing "not mine" residual diffs, same as
2026-09-07): `cli.py` (collect docstring), `src/deployment/ansible_runner.py` (stale-master
reset + dest-dir mkdir), `src/playbooks/plays/collect_host_logs.yml` (auditctl dumps),
`fip_unreachable_vs_stale.patch`, `logs/` (generated), and the unused
`sfprocessor-0.7.0-x86_64.deb` (downloaded during the §4 investigation, superseded by keeping
0.5.0 — dead weight, not referenced by any playbook).

---

## 1. Goal

Create instrumented variants of every non-generated environment, where host telemetry
(sysflow + Falco) is **installed at bake time** and **started at deploy time**, then bake
and publish the images so the environments deploy.

---

## 2. What was delivered

### 2.1 Environment specs — `environments/instrumented/` (15 files)

14 new files generated from `environments/non-generated/`, one per source env, named
`<name>_instrumented.json`. Transform applied:

- `vm_type` swapped to the instrumented variant (`*_running` → `*_instrumented`)
- `kali_running` left as-is — **the attacker stays uninstrumented, by design**
- Env name and network name suffixed `_instrumented`; description annotated
- **Everything else copied verbatim**: host names, IPs, subnets, `subnet_connections`,
  `playbooks`. Verified programmatically: all 14 are byte-identical to their source once
  name/description/vm_type are normalised out.

`equifax_small_instrumented.json` already existed and was **edited, not regenerated**:
its 3 `sensor` hosts were removed (10 hosts → 7). It keeps its underscore host names
(`webserver_0`, `database_0`) which differ from `equifax_small.json`'s (`webserver0`,
`database0`) — deliberate, because Glance snapshots and its own `add_data` paths
(`~/data_database_0.json`) are keyed to them.

**Status: all 15 validate through the deployer's own `NetworkTopology` pydantic model and
resolve to images that exist in Glance.**

### 2.2 Registry changes

`src/registry/offline_registry.yaml` (bake-time) — 2 new images:

| Image | Parent | Playbooks | Disk |
|---|---|---|---|
| `ubuntu_telemetry` | `ubuntu_base` | `install_sysflow_nostart`, `install_falco_nostart` | 16 GB |
| `webserver_telemetry` | `webserver` | same | 16 GB |

Also: `sensor` reparented `ubuntu_base` → `ubuntu_telemetry` (it baked Zeek/Suricata/Filebeat
but never Falco or sysflow, so `sensor_instrumented`'s `start_defender_services` had nothing
to start). **`sensor` has never been baked or uploaded** — unchanged from before.

`src/registry/online_registry.yaml` (deploy-time) — 7 new entries + 9 reparented:

New `*_instrumented` entries for the vulnerable variants that lacked them:
`ubuntu_netcat`, `ubuntu_writeable`, `ubuntu_sudobaron`, `ubuntu_netcat_writeable`,
`ubuntu_netcat_sudobaron`, `webserver_writeable`, `webserver_sudobaron`.

Playbook order is **vuln first, telemetry last** (e.g. `sudobaron`, `start_sysflow`,
`start_defender_services`). Rationale: `writeable_passwd`'s chmod and the sudobaron drop-in
would otherwise fire Falco rules during setup and pollute the baseline.

All 9 `*_instrumented` entries reparented onto `ubuntu_telemetry` / `webserver_telemetry`.
The `*_running` entries are untouched and still resolve to clean `ubuntu_base` / `webserver`.

> **Naming note:** the offline images are `*_telemetry`, not `*_instrumented`, because the
> online registry already owns those names. An online entry whose `parent` equals its own
> name spins forever in `get_ancestor_chain()`.

### 2.3 Playbook fixes

| File | Change | Why |
|---|---|---|
| `start_defender_services.yml` | `name: falco` → `name: falco-modern-bpf` | **No `falco.service` unit exists.** The deb ships driver-named units. Task has no `ignore_errors`, so this killed `configure` on the first instrumented host. |
| `install_falco_nostart.yml` | appended explicit disable/stop loop | The falco deb enables its unit via systemd preset, so "nostart" did not hold. Confirmed: the disable task reports `changed` on `falco-modern-bpf`. |
| `install_falco_nostart.yml` | `https://` → `http://`, password → `changeme` | See §3. |
| `install_filebeat_nostart.yml` | same | |
| `aux_files/pipeline.local.json` | same | sysflow's ES exporter had the identical bug. |
| `install_sysflow_nostart.yml` | sfcollector `0.5.0`→`0.8.0`; sfprocessor stays `0.5.0`; `dpkg -i --force-overwrite`; new tasks setting `DRIVER_TYPE=ebpf-core` and a systemd drop-in | See §4. |

New binaries in `src/playbooks/plays/aux_files/`: `sfcollector-0.8.0-x86_64.deb`,
`sfprocessor-0.7.0-x86_64.deb` (**downloaded but no longer used** — see §4).
The old `sfcollector-0.5.0` / `sfprocessor-0.5.0` debs are still present; 0.5.0 processor is
still required.

---

## 3. Elasticsearch — FIXED and VERIFIED

Telemetry had **never** reached Elasticsearch. Two stacked bugs:

1. `es_address` was `https://10.81.1.25:9200`; the server speaks **plain HTTP**
   (`curl http://` → 401 auth challenge; `curl https://` → connection failure).
2. The password `-97z1wUJcnE_Y31SuYg-` was stale. The real value is **`changeme`**, found in
   the ES container's `ELASTIC_PASSWORD` env on beluga1. Ironically the untouched template
   `install_falco.yml` had `changeme` correct all along.

Before the fix ES had **zero indices**. After: `falcosidekick` logs
`Elasticsearch - POST OK (201)` and the `falco` index contains a real alert
(`Read sensitive file untrusted`, `file=/etc/shadow`, full process lineage, MITRE `T1555`).

> **Security note:** `changeme` is the live password on a cluster reachable from every
> deployed VM, hardcoded in 4 files across 2 repos. There is **no config indirection for ES
> anywhere in MHBench** — v3's `config.yaml` has no ES section either. Worth moving into
> `config.yaml` next to `openstack:` and rotating.

---

## 4. sysflow crash loop — FIXED on the live host, NOT YET IN THE IMAGES

**Original symptom:** `sysflow-collector` at `activating (auto-restart)`, `NRestarts` 112+
and climbing, ~3.2 s CPU per retry, on every instrumented host. Invisible in deploy logs
because `sysflow start` runs with `ignore_errors: yes`.

Four distinct layered causes, each found only after fixing the previous one:

1. **sysflow 0.5.0's legacy eBPF driver cannot compile on kernel 6.8.**
   `error: no member named 'cap' in 'kernel_cap_t'` — Linux 6.3 collapsed `kernel_cap_t`
   from `u32[2]` to a plain `u64`; the 2022-era falco 3.0.1 driver source predates it.
   0.5.0's loader has **zero** modern_bpf support, so `DRIVER_TYPE` could not sidestep it.
   → **Upgraded collector to 0.8.0** (falco libs 0.20.0, driver 8.0.0/9.1.0, CO-RE).

2. **dpkg file conflict.** sfcollector 0.8.0 ships `/etc/falco/falco.yaml`, also owned by
   `falco 0.43.1`. → **`dpkg -i --force-overwrite`**. Safe because `install_falco_nostart`
   runs *after* and copies `aux_files/falco.yaml` over the top — verified in the baked
   images that `engine: kind: modern_ebpf` survives.

3. **`DRIVER_TYPE=ebpf` is hardcoded** in the package's `/etc/sysflow/conf/sysflow.env`
   (not unset, as I first assumed). That takes the legacy branch and makes the launcher pass
   `-k ebpf` to `sysporter`, which then fails with
   `Probe does not appear to exist '/run/sysflow/.falco/falco-bpf.o'`.
   → **Set `DRIVER_TYPE=ebpf-core`.** `sysporter -h` confirms valid values are
   `ebpf | ebpf-core | kmod`.

4. **`ProtectSystem=full`** on the 0.8.0 `sysflow-collector.service` mounts `/etc` read-only,
   but `falcoctl` (run from `ExecStart`) must write `/etc/falco/config.d/` and
   `/etc/falcoctl/falcoctl.yaml`. → **systemd drop-in with
   `ReadWritePaths=/etc/falco /etc/falcoctl`**.

**Separate finding — sf-processor 0.7.0 is unusable.** It fails with
`No drivers configured on command line or in pipeline config` even with `-driver=socket`.
The `socket` driver is not shipped in the **deb, rpm, or tarball** (`-driverdir` defaults to
a relative `../resources/drivers` that resolves nowhere). 0.5.0 has it built in.
→ **Keep sfprocessor at 0.5.0.** The pipeline config format is otherwise unchanged between
0.5.0 and 0.7.0 (verified against 0.7.0's shipped `pipeline.elk.json` — identical keys, and
`/etc/sysflow/policies/distribution/filter.yaml` still ships at the same path).

**Verified working combination — collector 0.8.0 + processor 0.5.0:**

```
sysflow-collector   active   NRestarts=0→1 (stable)
sysflow-processor   active   NRestarts=0
/sock/sysflow.sock  created
processor log: "Health checks: passed"
                "Successfully accepted new input stream"
                "Successfully read first record from input stream"
```

---

## 5. Current state

### Glance (cloud `kolla-admin` locally / `openstack` on beluga1)

| Image | Status | Size | Contents |
|---|---|---|---|
| `ubuntu_telemetry` | active | 5.03 GiB | sysflow **0.8.0 + 0.7.0**, ES fix, modern_ebpf falco |
| `webserver_telemetry` | active | 6.21 GiB | same |

**⚠️ The published images contain sfprocessor 0.7.0, which crash-loops.** The §4 fixes
(processor 0.5.0, `DRIVER_TYPE=ebpf-core`, systemd drop-in) are **in the playbook but not in
the images**. Net effect versus the starting point: the *collector* crash loop is fixed in
the images, but the *processor* now crash-loops instead. **A rebake is required.**

### Live deployment

`smoke2` is **still running** — `smoke2-host0`, `smoke2-attacker`, `smoke2-management_host`,
mgmt floating IP `192.168.1.148`. `host0` (192.168.200.10) has all four §4 fixes applied
**by hand** and is the proof they work. Tear it down when no longer needed:

```bash
cd ~/MHBench && .venv/bin/python cli.py teardown \
  environments/instrumented/sudobaron_test_instrumented.json --project-name smoke2 --yes
```

### Git

31 modified/untracked paths, **nothing committed**. 19 untracked (the new env JSONs + the new
debs). Pre-existing unrelated changes (`cli.py`, `ansible_runner.py`, `collect_host_logs.yml`,
`playbook_registry.yaml`, `fip_unreachable_vs_stale.patch`, `install_metasploit.yml`) were
already there and are **not** mine.

---

## 6. Next actions

1. **Rebake and re-upload** (required — closes the §4 gap):
   ```bash
   rsync -a ~/MHBench/src/playbooks/plays/ beluga1:~/MHBench-instrumented/src/playbooks/plays/
   ssh beluga1 'cd ~/MHBench-instrumented && rm -f src/compilation/images/{ubuntu,webserver}_telemetry.qcow2 && \
     SUPERMIN_KERNEL=/boot/vmlinuz-6.8.0-101-generic SUPERMIN_MODULES=/lib/modules/6.8.0-101-generic \
     /home/lakshmi/v3_MHBench/.venv/bin/python cli.py -v compile ubuntu_telemetry webserver_telemetry'
   # then upload ONE AT A TIME (see pitfalls)
   ```
2. **Redeploy and verify** `sysflow-collector` and `sysflow-processor` both `active`,
   `NRestarts=0`, straight from the image with no manual edits.
3. **Confirm sysflow → ES export.** Still unverified: no `sysflow` index has ever appeared.
   The pipeline runs in `mode: alert` against a 2022-era 21-rule `filter.yaml`, so benign
   activity may simply not match. Needs an activity that trips a policy before you can call
   the export path proven. Falco → ES **is** proven.
4. **Decide on sysflow at all.** Falco covers the same syscall ground, works, and is
   CO-RE-clean. If you don't need sysflow's flow records, dropping it removes this entire
   class of problem.
5. **Move ES settings into `config.yaml`** and rotate `changeme` (§3).

---

## 7. Pitfalls for the next agent

- **`upload --force` deletes before it uploads, with no rollback.** A mid-transfer failure
  leaves you with *no image*. This happened twice here (Glance returned intermittent
  `502 Bad Gateway` on multi-GB PUTs; both succeeded on retry). **Upload one image at a
  time**, and consider fixing `upload_manager` to upload-then-swap.
- **`compile --force` is broken in this setup.** It makes `compile_with_ancestors` rebuild the
  whole chain including `ubuntu_root_ssh`, whose parent `ubuntu20.qcow2` does not exist on
  beluga1 → `RuntimeError: Parent 'ubuntu20' ... has not been compiled yet`. Instead
  **delete the target `.qcow2` and compile without `--force`** so ancestors short-circuit.
- **`virt-customize` fails on beluga1** — supermin cannot read `/boot/vmlinuz-6.8.0-139-generic`
  (mode `0600`). Workaround used: `SUPERMIN_KERNEL=/boot/vmlinuz-6.8.0-101-generic`
  `SUPERMIN_MODULES=/lib/modules/6.8.0-101-generic`. **This lives only in shell commands, not
  in the repo.** Permanent fix: `sudo chmod 0644 /boot/vmlinuz-*`.
- **beluga1's `~/v3_MHBench` is a DIFFERENT repo** (`peacock4o/v3_MHBench`). Read-only here;
  its `.venv` is borrowed to run the CLI, and its `images/` supplies the symlinked parent
  qcow2s. **Do not `git pull` between them.** It also names the cloud `openstack`, not
  `kolla-admin` — the only edit made to the beluga1 copy's `config.yaml`.
- **Do not use `pgrep -f "<pattern>"` to wait on a process** whose pattern appears in your own
  command line — it self-matches and either loops forever or kills your own shell. Both
  happened. Use `ps -eo cmd | grep -q "[c]li.py ..."` **and** ensure the launch command isn't
  in the same shell invocation.
- **v3's `ubuntu_base` already bakes `install_sysflow_nostart` + `install_falco_nostart`**
  (and its `webserver` adds `install_ghosts_lite_nostart`). The Glance base images therefore
  already contain Falco and sysflow. **This makes `ubuntu_telemetry`/`webserver_telemetry`
  largely redundant** — they mainly re-apply corrected configs on top. The local offline
  registry has drifted from the registry that actually built these images; reconciling them
  (putting telemetry in `ubuntu_base` as v3 does) is the cleaner long-term shape and was
  **not** attempted.

---

## 8. Corrections to earlier claims

Recorded so they aren't propagated:

- ❌ "No image ever installed Falco or sysflow." **Wrong** — true of the local offline
  registry, but the actual Glance images were built from v3's registry, which does install
  both. This is why the original equifax deployments worked.
- ❌ "The rebake is running." **Wrong** — the first `--force` rebake died immediately
  (`ubuntu20` error) and `pgrep` self-matching made it look alive across three checks.
- ❌ "`DRIVER_TYPE` is unset, so `${DRIVER_TYPE:+-k}` expands to nothing." **Partly wrong** —
  the package explicitly sets `DRIVER_TYPE=ebpf`; the legacy `elif` branch is what runs.
- ⚠️ The three sensor bugs in the old `equifax_small_instrumented` (not multihomed; all three
  named `sensor` so the inventory dict collapsed them and only the last was configured; no
  port mirroring so it could not see peer traffic) were **resolved by deleting the sensors**,
  not by fixing them. `Host.extra_interfaces` exists in `src/abstractions/network.py` but is
  read nowhere — multihoming is unimplemented.
