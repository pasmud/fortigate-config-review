"""Ordered review and reference checks for the IPv4 address namespace."""

from dataclasses import dataclass

from .parser import Config, Group, Policy

BUILTIN_ADDRESSES = frozenset({"all"})
POLICY_ADDRESS_FIELDS = ("srcaddr", "dstaddr")
GROUP_ADDRESS_FIELDS = ("member", "exclude-member")
POLICY_DEFAULTS = {
    "action": ("deny",),
    "status": ("enable",),
    "nat": ("disable",),
    "srcaddr-negate": ("disable",),
    "dstaddr-negate": ("disable",),
    "service-negate": ("disable",),
}


@dataclass(frozen=True)
class Finding:
    code: str
    line: int
    record: str
    key: str | int
    field: str | None = None
    reference: str | None = None


def policy_settings(policy: Policy) -> dict[str, tuple[str, ...]]:
    """Fill selected defaults without replacing explicit values."""
    return POLICY_DEFAULTS | policy.settings


def _group_cycles(groups: dict[str, Group]) -> list[Finding]:
    # Iterative DFS keeps deep exported group chains off Python's call stack.
    active: set[str] = set()
    done: set[str] = set()
    findings = []
    edges = {
        name: [(field, ref) for field in GROUP_ADDRESS_FIELDS
               for ref in group.settings.get(field, ()) if ref in groups]
        for name, group in groups.items()
    }
    for root in groups:
        if root in done:
            continue
        active.add(root)
        stack = [(root, iter(edges[root]))]
        while stack:
            name, neighbors = stack[-1]
            edge = next(neighbors, None)
            if edge is None:
                stack.pop()
                active.remove(name)
                done.add(name)
                continue
            field, ref = edge
            if ref in active:
                findings.append(Finding("group-cycle", groups[name].line, "group", name,
                                        field, ref))
            elif ref not in done:
                active.add(ref)
                stack.append((ref, iter(edges[ref])))
    return findings


def validate(config: Config) -> tuple[Finding, ...]:
    """Check configured address/group references, including disabled policies."""
    addresses = {address.name for address in config.addresses}
    groups = {group.name: group for group in config.groups}
    known = addresses | groups.keys() | BUILTIN_ADDRESSES
    findings = [
        Finding("address-name-collision", group.line, "group", group.name)
        for group in config.groups if group.name in addresses or group.name in BUILTIN_ADDRESSES
    ]
    for policy in config.policies:
        for field in POLICY_ADDRESS_FIELDS:
            if field not in policy.settings:
                findings.append(Finding("missing-address-list", policy.line, "policy",
                                        policy.id, field))
    records = (
        (("group", group.name, group.line, group.settings, GROUP_ADDRESS_FIELDS)
         for group in config.groups),
        (("policy", policy.id, policy.line, policy.settings, POLICY_ADDRESS_FIELDS)
         for policy in config.policies),
    )
    for batch in records:
        for kind, key, line, settings, fields in batch:
            for field in fields:
                for ref in dict.fromkeys(settings.get(field, ())):
                    if ref not in known:
                        findings.append(Finding("unknown-address-reference", line, kind, key,
                                                field, ref))
    findings.extend(_group_cycles(groups))
    return tuple(sorted(findings, key=lambda finding: finding.line))
