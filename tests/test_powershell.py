import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SAMPLE = "config firewall policy\nedit 51\nset srcaddr all\nset dstaddr all\nnext\nend\n"


@pytest.fixture(scope="module")
def pwsh():
    if command := shutil.which("pwsh"):
        return command
    if os.environ.get("FORTIGATE_REQUIRE_PWSH") == "1":
        pytest.fail("Hosted PowerShell is required for wrapper checks")
    pytest.skip("PowerShell 7.4+ is not installed")


def invoke(pwsh, cwd, script, *arguments, python=sys.executable):
    return subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(SCRIPTS / script),
         "-Python", python, *arguments],
        cwd=cwd, capture_output=True, text=True, check=False, timeout=30,
    )


def test_summary_wrapper_resolves_relative_literal_path_and_streams_json(pwsh, tmp_path):
    path = tmp_path / "Fictional [site] backup.txt"
    path.write_text(SAMPLE, encoding="utf-8")
    result = invoke(pwsh, tmp_path, "Get-FortiGateSummary.ps1", "-Path", path.name,
                    "-Format", "Json")
    assert result.returncode == 0 and not result.stderr, result.stderr
    assert json.loads(result.stdout)["policies"][0]["id"] == 51


def test_summary_wrapper_status_filter_matches_cli_and_preserves_findings(pwsh, tmp_path):
    path = tmp_path / "Fictional [site] backup.txt"
    path.write_text('''config firewall policy
    edit 51
        set srcaddr Ghost
        set dstaddr all
    next
    edit 7
        set status disable
        set srcaddr all
        set dstaddr all
    next
end
''', encoding="utf-8")
    result = invoke(pwsh, tmp_path, "Get-FortiGateSummary.ps1", "-Path", path.name,
                    "-Format", "Json", "-PolicyStatus", "Disable")
    direct = subprocess.run(
        [sys.executable, "-m", "fortigate_review", "summary", "--format", "json",
         "--policy-status", "disable", str(path)],
        cwd=SCRIPTS.parent, capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == direct.returncode == 1 and not result.stderr, result.stderr
    report = json.loads(result.stdout)
    assert report == json.loads(direct.stdout)
    assert [p["id"] for p in report["policies"]] == [7]
    assert [f["key"] for f in report["findings"]] == [51]


def test_diff_wrapper_propagates_clean_change_status(pwsh, tmp_path):
    (tmp_path / "old backup.txt").write_text(SAMPLE, encoding="utf-8")
    (tmp_path / "new backup.txt").write_text(SAMPLE.replace("51", "90"), encoding="utf-8")
    arguments = ("-Before", "old backup.txt", "-After", "new backup.txt", "-Format", "Json")
    result = invoke(pwsh, tmp_path, "Compare-FortiGatePolicy.ps1", *arguments, "-FailOnChange")
    assert result.returncode == 3 and not result.stderr, result.stderr
    assert json.loads(result.stdout)["added"] == [90]
    assert invoke(pwsh, tmp_path, "Compare-FortiGatePolicy.ps1", *arguments).returncode == 0


def test_summary_wrapper_preserves_input_and_reference_errors(pwsh, tmp_path):
    (tmp_path / "broken backup.txt").write_text(SAMPLE.replace("srcaddr all", "srcaddr Ghost"),
                                               encoding="utf-8")
    result = invoke(pwsh, tmp_path, "Get-FortiGateSummary.ps1", "-Path", "broken backup.txt",
                    "-Format", "Json")
    assert result.returncode == 1 and not result.stderr, result.stderr
    assert json.loads(result.stdout)["findings"][0]["reference"] == "Ghost"
    missing = invoke(pwsh, tmp_path, "Get-FortiGateSummary.ps1", "-Path", "missing backup.txt")
    assert missing.returncode == 2 and not missing.stdout
    assert "readable regular file" in missing.stderr


def test_wrapper_reports_missing_python(pwsh, tmp_path):
    result = invoke(pwsh, tmp_path, "Get-FortiGateSummary.ps1", "-Path", "fiction.txt",
                    python="no-such-fictional-python-executable")
    assert result.returncode == 2 and not result.stdout
    assert "could not invoke the review CLI" in result.stderr
