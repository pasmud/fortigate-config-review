import json
import subprocess
import sys

import pytest

POLICY = """config firewall policy
    edit 17
        set name "Fictional review"
        set srcaddr all
        set dstaddr all
        set comments "ignored fictional comment"
    next
end
"""


def invoke(*args):
    return subprocess.run([sys.executable, "-m", "fortigate_review", *args],
                          capture_output=True, text=True, check=False)


def test_summary_json_and_text_for_file_with_spaces(tmp_path):
    path = tmp_path / "Fictional Site 1.txt"
    path.write_text(POLICY, encoding="utf-8")
    result = invoke("summary", "--format", "json", "--", str(path))
    assert result.returncode == 0 and not result.stderr
    assert "ignored fictional comment" not in result.stdout
    report = json.loads(result.stdout)
    assert report["counts"] == {"addresses": 0, "groups": 0, "policies": 1,
                                "services": 0, "service_groups": 0}
    assert report["policies"][0]["id"] == 17
    assert report["policies"][0]["settings"]["action"] == ["deny"]
    assert report["policy_status_filter"] is None
    assert report["findings"] == []
    text = invoke("summary", str(path))
    assert text.returncode == 0 and "Policies (export order):" in text.stdout
    assert '17 (line 2): name=["Fictional review"]' in text.stdout


def test_summary_counts_configured_services_without_a_policy_table(tmp_path):
    path = tmp_path / "services.txt"
    path.write_text('''config firewall service custom
    edit "Review Web"
        set tcp-portrange 8443
    next
end
config firewall service group
    edit "Review Suite"
        set member "Review Web"
    next
end
''', encoding="utf-8")
    result = invoke("summary", str(path), "--format", "json")
    assert result.returncode == 0 and not result.stderr
    report = json.loads(result.stdout)
    assert report["counts"]["services"] == report["counts"]["service_groups"] == 1
    assert report["has_policy_table"] is False


def test_status_filter_keeps_export_order_and_full_review_scope(tmp_path):
    path = tmp_path / "mixed status.txt"
    path.write_text('''config firewall address
    edit "Held by disabled policy"
    next
end
config firewall service custom
    edit "Review Web"
    next
end
config firewall policy
    edit 91
        set srcaddr all
        set dstaddr all
    next
    edit 4
        set status disable
        set srcaddr "Held by disabled policy"
        set dstaddr all
        set service "review web"
    next
    edit 23
        set status enable
        set srcaddr all
        set dstaddr all
    next
end
''', encoding="utf-8")
    result = invoke("summary", "--policy-status", "enable", "--format", "json", str(path))
    assert result.returncode == 1 and not result.stderr
    report = json.loads(result.stdout)
    assert report["policy_status_filter"] == "enable"
    assert report["counts"]["policies"] == 3
    assert [p["id"] for p in report["policies"]] == [91, 23]
    assert [f["key"] for f in report["findings"]] == [4]
    assert report["unused_addresses"]["candidates"] == []
    assert report["unused_addresses"]["withheld_reason"] is None


def test_status_filter_reports_empty_selection_and_rejects_invalid_value(tmp_path):
    path = tmp_path / "one policy.txt"
    path.write_text(POLICY, encoding="utf-8")
    result = invoke("summary", "--policy-status", "disable", str(path))
    assert result.returncode == 0 and not result.stderr
    assert "Policies (export order; status=disable; showing 0 of 1):" in result.stdout
    assert "17 (line" not in result.stdout
    invalid = invoke("summary", "--policy-status", "unknown", str(path))
    assert invalid.returncode == 2 and "invalid choice" in invalid.stderr and not invalid.stdout


def test_diff_status_precedence_and_side_specific_findings(tmp_path):
    before = tmp_path / "before.txt"
    after = tmp_path / "after.txt"
    before.write_text(POLICY, encoding="utf-8")
    after.write_text(POLICY.replace("set srcaddr all", "set srcaddr MissingExample"), encoding="utf-8")
    result = invoke("diff", str(before), str(after), "--format", "json", "--fail-on-change")
    assert result.returncode == 1 and not result.stderr
    data = json.loads(result.stdout)
    assert data["has_changes"] and data["findings"]["before"] == []
    assert data["findings"]["after"][0]["reference"] == "MissingExample"
    assert data["changed"][0]["fields"]["srcaddr"] == {"before": ["all"], "after": ["MissingExample"]}
    result = invoke("summary", str(after))
    assert result.returncode == 1 and "address-reference-findings" in result.stdout


def test_service_findings_fail_the_report_without_withholding_address_candidates(tmp_path):
    shared = '''config firewall address
    edit "Review Label"
    next
end
config firewall service custom
    edit "Review Web"
    next
end
'''
    before = tmp_path / "before.txt"
    after = tmp_path / "after.txt"
    before.write_text(shared + POLICY, encoding="utf-8")
    altered = POLICY.replace("set dstaddr all", 'set dstaddr all\n        set service "review web"')
    after.write_text(shared + altered, encoding="utf-8")
    summary = invoke("summary", "--format", "json", str(after))
    assert summary.returncode == 1 and not summary.stderr
    report = json.loads(summary.stdout)
    assert [f["code"] for f in report["findings"]] == ["service-reference-case-mismatch"]
    assert report["unused_addresses"]["candidates"] == ["Review Label"]
    diff = invoke("diff", "--fail-on-change", str(before), str(after))
    assert diff.returncode == 1 and not diff.stderr
    assert "Before findings: 0" in diff.stdout and "After findings: 1" in diff.stdout


def test_diff_only_fails_on_clean_change_when_requested(tmp_path):
    before = tmp_path / "before.txt"
    after = tmp_path / "after.txt"
    before.write_text(POLICY, encoding="utf-8")
    after.write_text(POLICY.replace("edit 17", "edit 18"), encoding="utf-8")
    assert invoke("diff", str(before), str(after)).returncode == 0
    result = invoke("diff", "--fail-on-change", str(before), str(after))
    assert result.returncode == 3 and "Added: [18]" in result.stdout
    assert invoke("diff", "--fail-on-change", str(before), str(before)).returncode == 0


@pytest.mark.parametrize(("content", "message"), [
    (None, "expected a readable regular file"),
    (b"\xff", "input must be UTF-8"),
    (b'config firewall address\nedit "not closed', "line 2: malformed token"),
])
def test_summary_input_failure_has_no_report(tmp_path, content, message):
    path = tmp_path / "fiction.txt"
    if content is not None:
        path.write_bytes(content)
    result = invoke("summary", str(path), "--format", "json")
    assert result.returncode == 2 and not result.stdout
    assert message in result.stderr and "Traceback" not in result.stderr


def test_cli_usage_error():
    result = invoke("summary")
    assert result.returncode == 2 and "usage:" in result.stderr and not result.stdout
