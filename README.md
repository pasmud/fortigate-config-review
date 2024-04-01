# FortiGate Config Review

An offline reviewer for local FortiOS text exports. Check selected address and service references, inspect policy order, compare policy IDs across backups, and find address objects worth reviewing for possible disuse. No appliance connections, configuration writes, or deployment commands. The included exports are entirely fictional.

## Quick start

Run from the repository root with Python 3.11 or newer. The core has no runtime dependencies.

```sh
python -m fortigate_review summary 'examples/Fictional Before.txt'
python -m fortigate_review diff --format json 'examples/Fictional Before.txt' 'examples/Fictional After.txt'
```

The summary lists policy IDs `42, 7, 31` in export order and suggests only `Spare Label` for follow-up. `Dormant Lab` is retained because a disabled policy refers to it, and `Group Shelf` is retained because a group refers to it even though no policy uses that group. The diff adds `56`, removes `31`, reports the `action` edit to `42`, and marks the surviving IDs as reordered. Policy `7`'s explicit `deny` matches its previous omitted action.

For a worked example with a reference finding, see the [synthetic review walkthrough](#synthetic-review-walkthrough).

The checkout also includes PowerShell 7.4+ entry points. `-Python` accepts a Python executable name or path when `python` is not the desired interpreter. The scripts resolve relative inputs from your current directory and run the core from the checkout. Invoke them normally, not by dot-sourcing.

```powershell
& ./scripts/Get-FortiGateSummary.ps1 -Path 'examples/Fictional Before.txt' -Format Json
& ./scripts/Get-FortiGateSummary.ps1 -Path 'examples/Fictional Before.txt' -PolicyStatus Disable
& ./scripts/Compare-FortiGatePolicy.ps1 -Before 'examples/Fictional Before.txt' -After 'examples/Fictional After.txt' -FailOnChange
$LASTEXITCODE # 3 for this fictional change
```

## Input contract

- A regular, local UTF-8 file (optional BOM, LF or CRLF), containing at least one reviewed table: `config firewall address`, `config firewall addrgrp`, `config firewall service custom`, `config firewall service group`, or `config firewall policy`. `diff` requires an explicit policy section in both inputs; an empty section is valid and means zero policies. Compare exports from the same logical firewall scope, where IDs are stable.
- Only one unnamed root scope is supported. Explicit `config vdom`/`config global` wrappers, non-`no-vdom` settings in `config system global`, and nested reviewed tables are rejected rather than merged.
- Reviewed tables contain flat `edit KEY` / `next` records with `set KEY VALUE [VALUE ...]` entries, and close with `end`. Indentation is optional. Blank lines and whole lines starting with `#` after indentation are ignored. Values can be bare tokens or double-quoted strings with `\"` and `\\` escapes. There are no inline comments, multiline values, or update commands such as `unset` and `move` in reviewed records. Policy IDs are ASCII decimals from 1 to 4294967294; equivalent IDs such as `7` and `07` are duplicates. Duplicate reviewed tables, record keys, or settings are rejected.
- Other tables are structurally checked for balanced blocks but their settings are not interpreted. Only selected settings are retained in reviewed records. Comparisons are case-sensitive; value token order is preserved.

## Checks and reports

**Summary.** Text shows inventory counts, an ordered policy outline, findings, and unused-address results. JSON includes `counts`, `has_policy_table`, `policies` (ID, `edit` line, and selected `settings` as token arrays), `findings`, and `unused_addresses`. Findings give a code, the one-based `edit` line, record type and ID/name, with a field and reference when relevant.

Use `summary --policy-status enable` or `summary --policy-status disable` to narrow the outline while preserving export order. In PowerShell, use `-PolicyStatus Enable` or `-PolicyStatus Disable`. Omitted policy status counts as `enable`. Inventory counts, findings, unused-address results, and exit status still cover the full export. JSON reports the requested `policy_status_filter`, or `null` when no filter was requested.

`counts.services` and `counts.service_groups` count records explicitly included in the export. The parser retains selected protocol, port-range, and ICMP settings for services and `member` for service groups. Service names and values can still hold same-named address objects for manual review as opaque mentions.

| Check | Scope |
| --- | --- |
| Address reference resolution | Policy `srcaddr` and `dstaddr`, and group `member` and `exclude-member`; disabled rules and inactive excludes are checked. The IPv4 `all` address is recognized whether implicit or exported. Missing policy address lists are findings, not inferred. |
| Namespace and cycles | An address/group name collision or a group named `all` is a finding. Group membership and exclusion edges are checked for cycles. |
| Service reference diagnostics | Checks explicit policy `service` lists (including disabled policies) and service group `member` lists. A reference with no exact match but a case-insensitive match to a configured name or `ALL` is a possible case mismatch. Service/group name collisions (including a group named `ALL`) and cycles through unambiguous, exact configured group names are findings. |
| Unused address candidates | Any policy or group reference retains an object, even if the rule is disabled or the group has no policy reference. A case-insensitive, whole-token name match in an ignored value or ignored edit key also keeps an object out of `candidates`, and is listed under `opaque_mentions` unless already referenced. `all` is not a candidate. Results are withheld when the policy section is absent or there are address reference findings; JSON gives `withheld_reason`. |

Service lists may be omitted, and a name absent from the export may be a built-in. Neither is flagged on its own. Service findings do not withhold address candidates.

An unused-address candidate is a prompt for manual review, not proof that an object is safe to remove. Ignored tables are not semantically analyzed; indirect or differently encoded references can be missed, and name coincidences can retain objects. Use complete, authorized local exports and treat both input and reports as sensitive.

**Diff.** Matches records by numeric policy ID. `added` and `changed` are in after-export order; `removed` is in before-export order. `before_order`/`after_order` include all IDs, while `common_order_changed` compares the relative order of just the IDs present in both inputs. A field change has `before` and `after` token arrays or `null` for an absent value. Findings are reported separately for each input. JSON also reports `has_changes`, independent of findings.

The selected policy fields are `name`, `status`, `action`, `srcintf`, `dstintf`, `srcaddr`, `dstaddr`, `srcaddr-negate`, `dstaddr-negate`, `schedule`, `service`, `service-negate`, `nat`, and `logtraffic`. Omitted `action` is normalized to `deny`, omitted `status` to `enable`, and omitted `nat` and the three negate flags to `disable`. Other omitted fields remain absent. The diff does not compare object or group definitions, resolve interface or schedule references, evaluate traffic, or guarantee equivalent behavior. A report with no findings is not a full FortiOS validation.

### Exit status

Reports go to stdout, command and input errors to stderr. PowerShell forwards the native CLI status. Findings take precedence over the optional change status.

| Code | Meaning |
| --- | --- |
| `0` | Report completed without reference findings. Changes alone do not fail by default. |
| `1` | Report completed with address or service reference findings in at least one input. |
| `2` | Invalid CLI arguments, unreadable or unsupported input, or missing policy table for comparison; no report. |
| `3` | Clean diff with reportable changes and `--fail-on-change` / `-FailOnChange` enabled. |

## Synthetic review walkthrough

1. Review the enabled outline in [the fictional service export](examples/Fictional%20Service%20Review.txt):

   ```sh
   python -m fortigate_review summary --policy-status enable 'examples/Fictional Service Review.txt'
   ```

   The inventory counts one service, one service group, and two policies. Only policy `73` appears in the outline, but the report exits `1`: disabled policy `11` names `preview suite`, while the configured group is `Preview Suite`. Use the finding's `edit` line (27) to locate the reference. `HTTPS` is not listed as a configured service, so its absence does not produce a finding. `Held Review Label` is still referenced by policy `11`; only `Spare Review Label` is an unused-address candidate for manual review.

2. Compare the separate fictional before/after pair and ask for a distinct status on changes:

   ```sh
   python -m fortigate_review diff --format json --fail-on-change 'examples/Fictional Before.txt' 'examples/Fictional After.txt'
   ```

   The command exits `3` with no reference findings. Review the added ID `56`, removed ID `31`, and policy `42`'s `action` change from `accept` to `deny`. `common_order_changed` is `true` because `42, 7` became `7, 42`, regardless of the addition and removal.

## Installation and tests

Install the command into an activated virtual environment from the repository root with `python -m pip install .`. Then run `fortigate-config-review summary 'examples/Fictional Before.txt'` in place of `python -m fortigate_review summary ...`. The Python wheel contains the CLI and core; the PowerShell scripts and examples are in the checkout and source distribution.

To develop, use `python -m pip install '.[dev]'` in your virtual environment, then run `python -m pytest -q` and `python -m ruff check .`. Wrapper integration tests skip if `pwsh` is unavailable locally. On pushes and pull requests, GitHub Actions requires hosted PowerShell on Ubuntu and Windows and smoke-tests the installed Python command outside the checkout.

### Offline regression vectors

Run `python -m pytest -q tests/test_regression_vectors.py` to check the synthetic exports in `tests/regression_vectors/`. Each JSON file is a standalone case with explicit FortiOS lines and hand-written expectations. The cases cover configured labels and aliases, built-in services, group exclusions and cycles, ignored categories, policy status and order, and ID-based comparison and reporting.

Summary cases check the named report fields and expect no findings unless stated. Finding rows are `[code, edit line, record type, key, field, reference]`. Inventory rows are `[name, edit line, settings]`. Diff cases check the entire report; omitted change lists and side-specific findings must be empty, and omitted `common_order_changed` must be false. To run one case, pass its filename stem to `-k`.

## License

[MIT](LICENSE).
