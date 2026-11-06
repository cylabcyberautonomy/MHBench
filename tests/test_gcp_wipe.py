"""GCPBackend.wipe(): the owner filter is what keeps a clean slate from deleting colleagues' runs in a
shared project, so it is checked against fake Compute clients holding mixed-ownership resources.

Rule under test: a resource's own JSON stamp decides; unstamped resources fall back to sitting on a
VPC stamped as yours.

Run: uv run --no-sync --with pytest python -m pytest tests/test_gcp_wipe.py
(--no-sync: a plain `uv run` re-syncs the venv and drops the gcp extra this needs)
"""
from types import SimpleNamespace as NS

from src.deployment.backends.gcp_backend import GCPBackend, _owner_of, _owner_stamp

ME, ELLA = "me@andrew.cmu.edu", "ellapark@andrew.cmu.edu"
URL = "https://www.googleapis.com/compute/v1/projects/p/global/networks/"


class FakeClient:
    """Lists canned resources and records every delete it is asked for."""

    def __init__(self, items=(), aggregated=None):
        self.items, self.aggregated, self.deleted = list(items), aggregated, []

    def list(self, project):
        return self.items

    def aggregated_list(self, project):
        return self.aggregated

    def delete(self, project, **kw):
        self.deleted.append(kw)
        return "op"


def inst(name, net, desc=""):
    return NS(name=name, description=desc, network_interfaces=[NS(network=URL + net)])


def make_backend():
    # Each VPC's stamp; every resource on it is unstamped (desc "") unless listed under EXTRA.
    nets = {
        "mine-vpc": _owner_stamp(ME),
        "ella-vpc": _owner_stamp(ELLA),
        "legacy-vpc": "",                  # created before stamping existed
        "junk-vpc": "made by hand {",      # not JSON
        "default": _owner_stamp(ME),       # never wiped, even if it somehow carried a stamp
    }
    extra = [
        inst("ella-guest", "mine-vpc", _owner_stamp(ELLA)),   # her stamp wins over sitting in my VPC
        inst("mine-stray", "legacy-vpc", _owner_stamp(ME)),   # my stamp wins over an unowned VPC
    ]
    b = object.__new__(GCPBackend)
    b._project, b._credentials = "p", None
    b._owner = lambda: ME
    b._wait = lambda op: None
    b._networks = FakeClient([NS(name=n, description=d) for n, d in nets.items()])
    b._instances = FakeClient(aggregated=[("zones/us-central1-a", NS(
        instances=[inst(f"vm-on-{n}", n) for n in nets] + extra))])
    b._routers = FakeClient(aggregated=[("regions/us-central1", NS(routers=[
        NS(name=f"rt-{n}", description="", network=URL + n) for n in nets]))])
    b._firewalls = FakeClient([NS(name=f"fw-{n}", description="", network=URL + n) for n in nets])
    b._subnetworks = FakeClient(aggregated=[("regions/us-central1", NS(subnetworks=[
        NS(name=f"sn-{n}", description="", network=URL + n) for n in nets]))])
    return b


def deleted(b):
    return {
        "instances": sorted(d["instance"] for d in b._instances.deleted),
        "routers": sorted(d["router"] for d in b._routers.deleted),
        "firewalls": sorted(d["firewall"] for d in b._firewalls.deleted),
        "subnets": sorted(d["subnetwork"] for d in b._subnetworks.deleted),
        "networks": sorted(d["network"] for d in b._networks.deleted),
    }


def test_default_wipe_takes_my_stamps_and_unstamped_resources_on_my_vpc():
    b = make_backend()
    b.wipe()
    assert deleted(b) == {
        # vm-on-mine-vpc: unstamped, on my VPC (fallback). mine-stray: my own stamp, unowned VPC.
        # ella-guest is NOT taken: her stamp beats sitting in my VPC.
        "instances": ["mine-stray", "vm-on-mine-vpc"],
        "routers": ["rt-mine-vpc"],
        "firewalls": ["fw-mine-vpc"],
        "subnets": ["sn-mine-vpc"],
        "networks": ["mine-vpc"],
    }
    # the scoped key ("zones/..."/"regions/...") is reduced to the bare zone/region the API wants
    assert {d["zone"] for d in b._instances.deleted} == {"us-central1-a"}
    assert b._routers.deleted[0]["region"] == "us-central1"


def test_wipe_all_ignores_ownership_but_spares_the_default_network():
    b = make_backend()
    b.wipe(everything=True)
    got = deleted(b)
    assert got["networks"] == ["ella-vpc", "junk-vpc", "legacy-vpc", "mine-vpc"]
    assert "sn-default" not in got["subnets"] and "fw-default" not in got["firewalls"]
    # --all takes every instance in the project, whoever stamped it and whatever network it is on
    assert "vm-on-default" in got["instances"] and "ella-guest" in got["instances"]
    assert len(got["instances"]) == 7


def test_stamp_round_trips_and_anything_else_is_not_owned():
    assert _owner_of(NS(description=_owner_stamp(ME))) == ME
    for desc in ("", None, "not json", "[]", '{"mhbench": {}}', '{"other": {"owner": "x"}}', '"str"'):
        assert _owner_of(NS(description=desc)) is None, desc
