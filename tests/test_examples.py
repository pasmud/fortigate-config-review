import json
from pathlib import Path

from fortigate_review.cli import main
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


def test_walkthrough_summary_shows_filtered_outline_and_full_review(capsys):
    assert main(["summary", "--policy-status", "enable",
                 str(EXAMPLES / "Fictional Service Review.txt")]) == 1
    report = capsys.readouterr()
    assert not report.err
    assert "1 services, 1 service_groups, 2 policies" in report.out
    assert "Policies (export order; status=enable; showing 1 of 2):" in report.out
    assert "73 (line " in report.out and "11 (line" not in report.out
    assert "Reference findings: 1" in report.out
    assert ('line 27: service-reference-case-mismatch: policy 11 service -> "preview suite"'
            in report.out)
    assert 'Unused address candidates: ["Spare Review Label"]' in report.out


def test_walkthrough_diff_reports_clean_change_exit_status(capsys):
    assert main(["diff", "--format", "json", "--fail-on-change",
                 str(EXAMPLES / "Fictional Before.txt"),
                 str(EXAMPLES / "Fictional After.txt")]) == 3
    report = capsys.readouterr()
    assert not report.err
    diff = json.loads(report.out)
    assert diff["findings"] == {"before": [], "after": []}
    assert diff["added"] == [56] and diff["removed"] == [31]
    assert diff["common_order_changed"] is True
    assert diff["changed"] == [
        {"id": 42, "fields": {"action": {"before": ["accept"], "after": ["deny"]}}},
    ]
