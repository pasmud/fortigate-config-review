"""Compare direct policy settings by ID, independently of sequence changes."""

from dataclasses import dataclass

from .parser import Config
from .review import policy_settings


class ComparisonError(ValueError):
    """One input lacks a policy table to compare."""


@dataclass(frozen=True)
class FieldChange:
    before: tuple[str, ...] | None
    after: tuple[str, ...] | None


@dataclass(frozen=True)
class PolicyChange:
    id: int
    fields: dict[str, FieldChange]


@dataclass(frozen=True)
class PolicyDiff:
    added: tuple[int, ...]
    removed: tuple[int, ...]
    changed: tuple[PolicyChange, ...]
    before_order: tuple[int, ...]
    after_order: tuple[int, ...]
    common_order_changed: bool

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed or self.common_order_changed)


def compare(before: Config, after: Config) -> PolicyDiff:
    """Treat inserts and deletes separately from reordering surviving IDs."""
    for label, config in (("before", before), ("after", after)):
        if not config.has_policy_table:
            raise ComparisonError(f"{label} input must contain an explicit firewall policy section")
    old = {policy.id: policy_settings(policy) for policy in before.policies}
    new = {policy.id: policy_settings(policy) for policy in after.policies}
    common_before = tuple(policy_id for policy_id in old if policy_id in new)
    common_after = tuple(policy_id for policy_id in new if policy_id in old)
    changed = []
    for policy_id in common_after:
        left, right = old[policy_id], new[policy_id]
        fields = {
            field: FieldChange(left.get(field), right.get(field))
            for field in sorted(left.keys() | right.keys()) if left.get(field) != right.get(field)
        }
        if fields:
            changed.append(PolicyChange(policy_id, fields))
    return PolicyDiff(
        added=tuple(policy_id for policy_id in new if policy_id not in old),
        removed=tuple(policy_id for policy_id in old if policy_id not in new),
        changed=tuple(changed),
        before_order=tuple(old),
        after_order=tuple(new),
        common_order_changed=common_before != common_after,
    )
