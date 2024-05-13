from pathlib import Path

from fortigate_review.diff import FieldChange, compare
from fortigate_review.parser import parse
from fortigate_review.review import unused_addresses, validate

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_readme_examples_match_documented_outcomes():
    before = parse((EXAMPLES / "Fictional Before.txt").read_text(encoding="utf-8"))
    after = parse((EXAMPLES / "Fictional After.txt").read_text(encoding="utf-8"))
    assert not validate(before) and not validate(after)
    assert unused_addresses(before).candidates == ("Spare Label",)
    diff = compare(before, after)
    assert diff.before_order == (42, 7, 31)
    assert diff.after_order == (7, 42, 56)
    assert diff.common_order_changed
    assert diff.added == (56,) and diff.removed == (31,)
    assert [(change.id, change.fields) for change in diff.changed] == [
        (42, {"action": FieldChange(("accept",), ("deny",))}),
    ]
