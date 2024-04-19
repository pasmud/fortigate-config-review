"""Ordered reference checks for addresses and configured services."""

from collections.abc import Mapping
from dataclasses import dataclass

from .parser import Config, Group, Policy, ServiceGroup

BUILTIN_ADDRESSES = frozenset({"all"})
BUILTIN_SERVICES = frozenset({"ALL"})
POLICY_ADDRESS_FIELDS = ("srcaddr", "dstaddr")
GROUP_ADDRESS_FIELDS = ("member", "exclude-member")
SERVICE_GROUP_FIELDS = ("member",)
ADDRESS_FINDING_CODES = frozenset({"address-name-collision", "missing-address-list",
                                   "unknown-address-reference", "group-cycle"})
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


@dataclass(frozen=True)
class UnusedAddresses:
    candidates: tuple[str, ...] = ()
    opaque_mentions: tuple[str, ...] = ()
    withheld_reason: str | None = None


def policy_settings(policy: Policy) -> dict[str, tuple[str, ...]]:
    """Fill selected defaults without replacing explicit values."""
    return POLICY_DEFAULTS | policy.settings


def _group_cycles(
    groups: Mapping[str, Group | ServiceGroup], fields: tuple[str, ...],
    *, code: str, record: str,
) -> list[Finding]:
    # Iterative DFS keeps deep exported group chains off Python's call stack.
    active: set[str] = set()
    done: set[str] = set()
    findings = []
    edges = {
        name: [(field, ref) for field in fields
               for ref in dict.fromkeys(group.settings.get(field, ())) if ref in groups]
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
                findings.append(Finding(code, groups[name].line, record, name, field, ref))
            elif ref not in done:
                active.add(ref)
                stack.append((ref, iter(edges[ref])))
    return findings


def _address_findings(config: Config) -> list[Finding]:
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
    findings.extend(_group_cycles(groups, GROUP_ADDRESS_FIELDS, code="group-cycle", record="group"))
    return findings


def _service_findings(config: Config) -> list[Finding]:
    services = {service.name for service in config.services} | BUILTIN_SERVICES
    groups = {group.name: group for group in config.service_groups}
    known = services | groups.keys()
    folded = {name.casefold() for name in known}
    findings = [Finding("service-name-collision", group.line, "service-group", group.name)
                for group in config.service_groups if group.name in services]
    records = (
        (("service-group", group.name, group.line, group.settings, "member")
         for group in config.service_groups),
        (("policy", policy.id, policy.line, policy.settings, "service")
         for policy in config.policies),
    )
    for batch in records:
        for kind, key, line, settings, field in batch:
            for ref in dict.fromkeys(settings.get(field, ())):
                # Absence from the export does not rule out an omitted built-in.
                if ref not in known and ref.casefold() in folded:
                    findings.append(Finding("service-reference-case-mismatch", line, kind, key,
                                            field, ref))
    unambiguous = {name: group for name, group in groups.items() if name not in services}
    findings.extend(_group_cycles(unambiguous, SERVICE_GROUP_FIELDS,
                                  code="service-group-cycle", record="service-group"))
    return findings


def validate(config: Config) -> tuple[Finding, ...]:
    """Check address and service references, including those on disabled policies."""
    findings = _address_findings(config) + _service_findings(config)
    return tuple(sorted(findings, key=lambda finding: finding.line))


def unused_addresses(
    config: Config, findings: tuple[Finding, ...] | None = None,
) -> UnusedAddresses:
    """Find addresses without an in-scope reference or an opaque name mention."""
    if not config.has_policy_table:
        return UnusedAddresses(withheld_reason="missing-policy-section")
    if findings is None:
        has_address_findings = bool(_address_findings(config))
    else:
        has_address_findings = any(f.code in ADDRESS_FINDING_CODES for f in findings)
    if has_address_findings:
        return UnusedAddresses(withheld_reason="address-reference-findings")
    referenced = set(BUILTIN_ADDRESSES)
    for records, fields in ((config.policies, POLICY_ADDRESS_FIELDS),
                            (config.groups, GROUP_ADDRESS_FIELDS)):
        for record in records:
            for field in fields:
                referenced.update(record.settings.get(field, ()))
    candidates = []
    opaque = []
    for address in config.addresses:
        if address.name in referenced:
            continue
        if address.name in config.opaque_address_mentions:
            opaque.append(address.name)
        else:
            candidates.append(address.name)
    return UnusedAddresses(tuple(candidates), tuple(opaque))
