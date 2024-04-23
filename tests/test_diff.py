import pytest

from fortigate_review.diff import ComparisonError, FieldChange, compare
from fortigate_review.parser import parse


def policies(*records):
    body = "\n".join(f"edit {key}\nset srcaddr all\nset dstaddr all\n{settings}\nnext"
                     for key, settings in records)
    return parse(f"config firewall policy\n{body}\nend")


def test_compare_matches_ids_and_reports_direct_edits_and_order():
    old = policies((41, 'set name "Fiction Lab"'), (8, "set action accept"), (3, ""))
    new = policies((8, "set action deny"), (72, ""), (41, 'set schedule "Fiction Hours"'))
    diff = compare(old, new)
    assert diff.has_changes
    assert diff.before_order == (41, 8, 3)
    assert diff.after_order == (8, 72, 41)
    assert diff.common_order_changed
    assert diff.added == (72,)
    assert diff.removed == (3,)
    assert [change.id for change in diff.changed] == [8, 41]
    assert diff.changed[0].fields == {"action": FieldChange(("accept",), ("deny",))}
    assert diff.changed[1].fields == {
        "name": FieldChange(("Fiction Lab",), None),
        "schedule": FieldChange(None, ("Fiction Hours",)),
    }


def test_add_remove_do_not_reorder_survivors_and_explicit_defaults_are_equivalent():
    old = policies((41, ""), (12, ""), (8, ""))
    new = policies((1, ""), (41, "set action deny\nset nat disable"), (8, "set status enable"))
    diff = compare(old, new)
    assert diff.added == (1,)
    assert diff.removed == (12,)
    assert not diff.changed
    assert not diff.common_order_changed


def test_reorder_only_and_non_reviewed_field_changes_are_distinct():
    old = policies((41, 'set comments "one"'), (8, ""))
    new = policies((8, ""), (41, 'set comments "two"'))
    diff = compare(old, new)
    assert diff.has_changes and diff.common_order_changed
    assert not (diff.changed or diff.added or diff.removed)
    assert not compare(old, policies((41, 'set comments "two"'), (8, ""))).has_changes


def test_empty_policy_section_is_intentional_but_omitted_section_is_ambiguous():
    absent = parse("config firewall address\nend")
    with pytest.raises(ComparisonError, match="after input"):
        compare(policies((1, "")), absent)
    assert compare(policies((1, "")), policies()).removed == (1,)
