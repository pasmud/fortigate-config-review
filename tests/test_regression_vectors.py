import json
from pathlib import Path

import pytest

from fortigate_review.cli import main
from fortigate_review.parser import parse

VECTORS = sorted(Path(__file__).with_name("regression_vectors").glob("*.json"))


def finding_rows(findings):
    columns = ("code", "line", "record", "key", "field", "reference")
    return [[finding[column] for column in columns] for finding in findings]


@pytest.mark.parametrize("path", VECTORS, ids=lambda path: path.stem)
def test_regression_vector(path, tmp_path, capsys):
    vector = json.loads(path.read_text(encoding="utf-8"))
    expected = vector["expected"]
    if vector["command"] == "inventory":
        config = parse("\n".join(vector["config"]))
        actual = {
            category: [
                [record.name, record.line, record.settings]
                for record in getattr(config, category)
            ]
            for category in expected
        }
        assert json.loads(json.dumps(actual)) == expected, vector["title"]
        return

    def backup(name, lines):
        target = tmp_path / f"{name}.conf"
        target.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
        return str(target)

    args = [vector["command"], "--format", "json", *vector.get("options", [])]
    if vector["command"] == "summary":
        args.append(backup("summary", vector["config"]))
    else:
        assert vector["command"] == "diff"
        args.extend(
            [backup("before", vector["before"]), backup("after", vector["after"])]
        )
    status = main(args)
    stdout, stderr = capsys.readouterr()
    assert status == expected["exit"], (vector["title"], stdout, stderr)
    if "error" in expected:
        assert not stdout
        assert stderr == f"error: {expected['error']}\n"
        return

    assert not stderr
    report = json.loads(stdout)
    if vector["command"] == "summary":
        report["findings"] = finding_rows(report["findings"])
        report["policy_ids"] = [policy["id"] for policy in report["policies"]]
        report["policy_lines"] = [policy["line"] for policy in report["policies"]]
        report.update(report.pop("unused_addresses"))
        expected = {"findings": [], **expected}
        actual = {key: (status if key == "exit" else report[key]) for key in expected}
    else:
        report["findings"] = {
            side: finding_rows(rows) for side, rows in report["findings"].items()
        }
        expected = {
            "added": [],
            "removed": [],
            "changed": [],
            "common_order_changed": False,
            "findings": {"before": [], "after": []},
            **expected,
        }
        actual = {"exit": status, **report}
    assert actual == expected, vector["title"]
