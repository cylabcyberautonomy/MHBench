# MHBench v3

Multi-host cybersecurity benchmark environment system. MHBench builds VM images, then provisions and configures multi-host network topologies from a single JSON spec. It supports two cloud backends: **OpenStack** (default) and **Google Cloud**.

## Prerequisites

- Python ≥ 3.12
- One cloud backend:
  - **OpenStack** — credentials in a `clouds.yaml` (default `~/.config/openstack/clouds.yaml`) and an SSH keypair registered with the cloud (see `openstack.keypair_name` / `openstack.ssh_key_path`).
  - **Google Cloud** — a GCP project, credentials (a service-account key or Application Default Credentials), and a local SSH keypair whose public key is injected into VM metadata. Install the extra with `uv sync --extra gcp`.

Ansible and all Python dependencies are installed automatically by `uv sync`.

## Installation

Dependencies are managed with [uv](https://docs.astral.sh/uv/). If you don't already have uv:

```bash
pip install uv
```

Clone the repo and sync the environment:

```bash
git clone https://github.com/cylabcyberautonomy/MHBench.git v3_MHBench
cd v3_MHBench
uv sync
source .venv/bin/activate
```

After this, the `mhbench` command is available inside the venv — every CLI example below uses it. If you'd rather not activate the venv, substitute `uv run mhbench` (or `python cli.py`) for `mhbench` in any command.

## Configuration

Copy the example config:

```bash
cp config/example_config.yaml config/config.yaml
```

Choose a backend with the top-level `backend:` key (`openstack` or `gcp`); it
defaults to `openstack`, so existing configs keep working unchanged.

**OpenStack** — fill in the four `openstack.*` fields:

| Field | What to set it to |
| --- | --- |
| `openstack.clouds_yaml` | Path to your OpenStack `clouds.yaml` |
| `openstack.cloud` | Name of the entry in `clouds.yaml` to use |
| `openstack.keypair_name` | SSH keypair registered on the cloud |
| `openstack.ssh_key_path` | Local path to the matching private key |

**Google Cloud** — set `backend: gcp` and fill in the `gcp.*` fields:

| Field | What to set it to |
| --- | --- |
| `gcp.project` | GCP project that owns the VMs, network and images |
| `gcp.region` / `gcp.zone` | Where subnetworks/NAT and VMs are created |
| `gcp.credentials_file` | Service-account key JSON (omit to use Application Default Credentials) |
| `gcp.ssh_key_path` | Local private key Ansible connects with |
| `gcp.ssh_public_key_path` | Public key injected into VM metadata (defaults to `<ssh_key_path>.pub`) |
| `gcp.image_bucket` | Cloud Storage bucket used to stage images during `upload` |
| `gcp.machine_type_map` | Maps OpenStack flavor names (used in specs) to GCP machine types |

See [How the GCP backend maps a topology](#how-the-gcp-backend-maps-a-topology) below.

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

All commands accept `--config PATH` (default `config/config.yaml`) and `-v/--verbose`. Run `mhbench --help` or `mhbench <command> --help` to see every option.

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

Validate a spec without touching the cloud:

```bash
mhbench deploy environments/non-generated/dumbbell.json --validate-only
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
    ├── deployment/         # cloud orchestrator
    │   └── backends/       # provider backends (openstack, gcp) behind one interface
    ├── playbooks/          # Ansible plays
    ├── registry/           # offline/online/playbook YAML registries
    └── abstractions/       # shared data models
```

## Backends

MHBench provisions through a single `CloudBackend` interface, chosen by the
`backend:` config key. The OpenStack path is unchanged from earlier versions;
the Google Cloud path implements the same interface with GCP primitives. The
CLI, Ansible configuration, topology specs, and registries are identical across
backends — only `config.yaml` changes.

### How the GCP backend maps a topology

| MHBench / OpenStack concept | Google Cloud resource |
| --- | --- |
| router + all networks | one custom-mode VPC network (`<project>-vpc`) |
| subnet | a regional subnetwork with the subnet's CIDR |
| security group + rules | VPC firewall rules targeted by network tag |
| internet egress for private VMs | a Cloud Router + Cloud NAT |
| management host floating IP | the management instance's external IP |
| OpenStack flavor (e.g. `m1.small`) | GCP machine type (via `gcp.machine_type_map`) |
| compiled image (e.g. `ubuntu_base`) | GCP image `ubuntu-base` (RFC1035-sanitized; override with `gcp.image_map`) |

Every resource is prefixed with `--project-name` exactly as on OpenStack, so
concurrent experiments never collide and teardown matches purely by name.

**Quick start.** Run the one-time project setup with
[scripts/gcp_bootstrap.sh](scripts/gcp_bootstrap.sh), which creates the service
account, roles, key, and staging bucket idempotently and prints the `gcp:`
config block to paste:

```bash
PROJECT_ID=my-mhbench-proj BILLING_ACCOUNT=XXXXXX-XXXXXX-XXXXXX \
  CREATE_PROJECT=1 ./scripts/gcp_bootstrap.sh
```

Then compile/upload the `ubuntu_base` image and deploy the tiny
Ubuntu-only smoke topology
[environments/non-generated/gcp_smoke.json](environments/non-generated/gcp_smoke.json):

```bash
uv sync --extra gcp
mhbench compile ubuntu_base && mhbench upload ubuntu_base
mhbench deploy environments/non-generated/gcp_smoke.json --project-name gcpsmoke -v
mhbench teardown environments/non-generated/gcp_smoke.json --project-name gcpsmoke --yes
```

Notes and current limitations:

- **Images.** Hosts boot from the *compiled* images, so upload them first with
  `mhbench upload`. On GCP `upload` converts the qcow2 to a raw disk, stages it
  in `gcp.image_bucket`, and registers it as a GCP image (equivalent to
  `gcloud compute images import` without the Cloud Build step). This needs
  `qemu-img` locally and the `google-cloud-storage` package (included in the
  `gcp` extra). Alternatively import images out of band and point at them with
  `gcp.image_map`.
- **DNS.** Per-subnet `dns_servers` in a spec are ignored on GCP; instances use
  GCP's internal resolver.
- **Guest hostname.** Set to `<host>.mhbench.internal`, keeping `hostname -s`
  equal to the spec host name (as on OpenStack).

## Troubleshooting

- **`Config file not found: config/config.yaml`** — copy `config/example_config.yaml` to `config/config.yaml` (see [Configuration](#configuration)).
- **Authentication / endpoint errors from OpenStack** — confirm `openstack.cloud` matches an entry in your `clouds.yaml` and that you can run `openstack server list` against the same cloud.
- **`google-cloud-compute` import error** — install the GCP extra: `uv sync --extra gcp`.
- **GCP auth / permission errors** — confirm `gcloud auth application-default login` (or `gcp.credentials_file`) works and the account has Compute Admin on `gcp.project`.
- **Teardown leaves resources behind** — `--project-name` must exactly match the value used at deploy time; resources are matched by that prefix.
- **Ansible failures during `deploy` / `configure`** — re-run with `-v` for debug logs, and verify the management host's floating IP is reachable on TCP/22 from your workstation.

## Support

Please open an issue on the project's issue tracker for bug reports and feature requests. Include the command you ran, the relevant log output (with `-v`), and the topology spec when applicable.
