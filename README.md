# MHBench v3

Multi-host cybersecurity benchmark environment system. MHBench builds VM images, then provisions and configures multi-host network topologies on OpenStack from a single JSON spec.

## Prerequisites

- Python ≥ 3.12
- An OpenStack cloud with credentials in `~/.config/openstack/clouds.yaml`
- An SSH keypair registered with the cloud (see `openstack.keypair_name` and `openstack.ssh_key_path` in `config/config.yaml`)
- Ansible 10.4.0 (installed automatically as a dependency)

## Installation

Dependencies are managed with [uv](https://docs.astral.sh/uv/). If you don't already have uv:

```bash
pip install uv
```

Then sync the environment:

```bash
cd v3_MHBench
uv sync
source .venv/bin/activate
```

This installs the `mhbench` console script (entry point `cli:cli`). You can also run the CLI directly with `python cli.py ...`.

## Configuration

Copy the example config:

```bash
cp config/example_config.yaml config/config.yaml
```

At minimum, fill in the four `openstack.*` fields that have no sensible default:

| Field | What to set it to |
| --- | --- |
| `openstack.clouds_yaml` | Path to your OpenStack `clouds.yaml` |
| `openstack.cloud` | Name of the entry in `clouds.yaml` to use |
| `openstack.keypair_name` | SSH keypair registered on the cloud |
| `openstack.ssh_key_path` | Local path to the matching private key |

Every other section ships with working defaults — see the inline comments in [config/example_config.yaml](config/example_config.yaml). You'd typically only revisit them when:

- `management` — the default management subnet (`10.0.1.0/24`) collides with something on your cloud, or you want a larger flavor / different base image for the jumpbox.
- `compilation.images_dir` — you want compiled `.qcow2` images written somewhere outside the repo (e.g. a larger disk).
- `registry.registry_dir` / `playbooks.playbooks_dir` — you're maintaining a fork with a custom registry or playbook layout.

## Concepts

- **Offline registry** ([src/registry/offline_registry.yaml](src/registry/offline_registry.yaml)) — VM images built ahead of time. Each entry declares a parent image and a list of playbooks layered on top. Plays here are **network-independent**: they install and configure software but never start anything that needs awareness of the live host (IP, user, peers). `compile` walks this graph to produce `.qcow2` files.
- **Online registry** ([src/registry/online_registry.yaml](src/registry/online_registry.yaml)) — runtime VM types that reference an offline image plus playbooks that run **after boot**, once the VM exists in its deployed topology. This is where services are started and host-specific state (credentials, shells, IP-aware config) is applied. Topology specs refer to these via `vm_type`.
- **Playbook registry** ([src/registry/playbook_registry.yaml](src/registry/playbook_registry.yaml)) — named Ansible plays available to both registries.
- **Environment spec** — a JSON file under [environments/](environments/) describing networks, subnets, hosts, and the VM type for each host. Examples live in [environments/non-generated/](environments/non-generated/) and [environments/generated/](environments/generated/).

## CLI

All commands accept `--config PATH` (default `config/config.yaml`) and `-v/--verbose`.

### Compile images

Builds offline-registry images in dependency order.

```bash
mhbench compile ubuntu_base webserver          # specific images (with ancestors)
mhbench compile --all                          # everything in the registry
mhbench compile --all --force                  # force rebuild
```

### Deploy a topology (provision + configure)

```bash
mhbench deploy environments/non-generated/dumbbell.json \
    --project-name my-experiment \
    --c2c-url http://10.0.0.1:8888
```

Flags:
- `--validate-only` — parse and validate the spec, then exit
- `--project-name` — prefix applied to every OpenStack resource name (use a unique value per experiment)
- `--c2c-url` — override the C2C server URL from config

### Provision only (no Ansible)

```bash
mhbench provision environments/non-generated/dumbbell.json \
    --project-name my-experiment \
    --output-file mgmt.json
```

`--output-file` writes `{"mgmt_ip": "..."}` with the management host's floating IP.

### Configure an already-provisioned topology

```bash
mhbench configure environments/non-generated/dumbbell.json \
    --project-name my-experiment \
    --mgmt-ip 1.2.3.4
```

### Tear down

```bash
mhbench teardown environments/non-generated/dumbbell.json \
    --project-name my-experiment --yes
```

The `--project-name` must match the value used at deploy time, or resources will not be matched for deletion.

## Typical workflow

```bash
# 1. Build images once
mhbench compile --all

# 2. Deploy an environment
mhbench deploy environments/non-generated/chain.json --project-name exp1

# 3. Run experiments against it...

# 4. Tear it down
mhbench teardown environments/non-generated/chain.json --project-name exp1 --yes
```

## Layout

```
v3_MHBench/
├── cli.py                  # Click entry point (mhbench)
├── config/config.yaml      # cloud + path configuration
├── environments/           # topology JSON specs
└── src/
    ├── compilation/        # offline image compiler
    ├── deployment/         # OpenStack orchestrator
    ├── playbooks/          # Ansible plays
    ├── registry/           # offline/online/playbook YAML registries
    └── abstractions/       # shared data models
```
