"""Compatibility alias for the NLS VIP table.

Earlier revisions called the temporary virtual-identity file an LSDB. The
routing LSDB is instead managed by FRR/OSPF; this module remains so existing
callers continue to work while the correct VIP-table name is used internally.
"""
from . import vip_table

# Kept assignable for older callers and tests which override the legacy path.
STATE_PATH = vip_table.STATE_PATH


def _table():
    vip_table.STATE_PATH = STATE_PATH
    return vip_table


def expire(now=None):
    return _table().expire(now)


def upsert(vip, router_id, original_ip, identity_public_key, expires_at, **kwargs):
    return _table().upsert(vip, router_id, original_ip, identity_public_key, expires_at, **kwargs)


def remove(vip):
    return _table().remove(vip)


def get(vip):
    return _table().get(vip)
