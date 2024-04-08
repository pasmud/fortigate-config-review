"""Local file input, report rendering, and command exit status."""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .diff import ComparisonError, compare
from .parser import Config, ParseError, parse
from .review import Finding, policy_settings, unused_addresses, validate


class InputError(ValueError):
    """An input could not be read or parsed."""


def _load(path: Path, label: str) -> Config:
    try:
        if not path.is_file():
            raise InputError(f"{label}: expected a readable regular file")
        with path.open(encoding="utf-8", newline="\n") as source:
            return parse(source.read())
    except ParseError as exc:
        raise InputError(f"{label}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"{label}: input must be UTF-8") from exc
    except OSError as exc:
        raise InputError(f"{label}: could not read input file") from exc


def _findings_text(findings: tuple[Finding, ...], label: str) -> list[str]:
    lines = [f"{label}: {len(findings)}"]
    for f in findings:
        field = f" {f.field}" if f.field is not None else ""
        ref = f" -> {json.dumps(f.reference)}" if f.reference is not None else ""
        lines.append(f"  line {f.line}: {f.code}: {f.record} {json.dumps(f.key)}{field}{ref}")
    return lines


def _summary(config: Config, output: str) -> int:
    findings = validate(config)
    unused = unused_addresses(config, findings)
    counts = {"addresses": len(config.addresses), "groups": len(config.groups),
              "services": len(config.services), "service_groups": len(config.service_groups),
              "policies": len(config.policies)}
    policies = [{"id": p.id, "line": p.line, "settings": policy_settings(p)}
                for p in config.policies]
    if output == "json":
        print(json.dumps({"counts": counts, "has_policy_table": config.has_policy_table,
                          "policies": policies, "findings": [asdict(f) for f in findings],
                          "unused_addresses": asdict(unused)}, indent=2, sort_keys=True))
    else:
        lines = ["Offline FortiGate summary", ", ".join(f"{v} {k}" for k, v in counts.items()),
                 "Policies (export order):"]
        for p in policies:
            fields = ("name", "status", "action", "srcaddr", "dstaddr")
            details = " ".join(f"{k}={json.dumps(p['settings'][k])}"
                               for k in fields if k in p["settings"])
            lines.append(f"  {p['id']} (line {p['line']}): {details}")
        lines.extend(_findings_text(findings, "Address reference findings"))
        if unused.withheld_reason:
            lines.append(f"Unused address candidates withheld: {unused.withheld_reason}")
        else:
            lines.append(f"Unused address candidates: {json.dumps(unused.candidates)}")
            lines.append(f"Held for opaque mentions: {json.dumps(unused.opaque_mentions)}")
        print("\n".join(lines))
    return 1 if findings else 0


def _diff(before: Config, after: Config, output: str, fail_on_change: bool) -> int:
    diff = compare(before, after)
    old_findings, new_findings = validate(before), validate(after)
    if output == "json":
        print(json.dumps(asdict(diff) | {"has_changes": diff.has_changes, "findings": {
            "before": [asdict(f) for f in old_findings], "after": [asdict(f) for f in new_findings],
        }}, indent=2, sort_keys=True))
    else:
        lines = ["Offline FortiGate policy diff (selected fields)",
                 f"Before order: {json.dumps(diff.before_order)}",
                 f"After order:  {json.dumps(diff.after_order)}",
                 f"Surviving IDs reordered: {'yes' if diff.common_order_changed else 'no'}",
                 f"Added: {json.dumps(diff.added)}", f"Removed: {json.dumps(diff.removed)}",
                 f"Policies with selected field changes: {len(diff.changed)}"]
        for change in diff.changed:
            lines.append(f"  Policy {change.id}:")
            for field, values in change.fields.items():
                lines.append(f"    {field}: {json.dumps(values.before)} -> {json.dumps(values.after)}")
        lines.extend(_findings_text(old_findings, "Before findings"))
        lines.extend(_findings_text(new_findings, "After findings"))
        print("\n".join(lines))
    if old_findings or new_findings:
        return 1
    return 3 if fail_on_change and diff.has_changes else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review local, root-scope FortiOS text exports.")
    commands = parser.add_subparsers(dest="command", required=True)
    summary = commands.add_parser("summary", help="list policies, findings, and unused candidates")
    summary.add_argument("backup", type=Path)
    diff = commands.add_parser("diff", help="compare selected policy fields and rule order")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--fail-on-change", action="store_true", help="exit 3 for a reportable change")
    for command in (summary, diff):
        command.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        if args.command == "summary":
            return _summary(_load(args.backup, "backup"), args.format)
        return _diff(_load(args.before, "before"), _load(args.after, "after"),
                     args.format, args.fail_on_change)
    except (InputError, ComparisonError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
