from fortigate_review.parser import parse
from fortigate_review.review import policy_settings, unused_addresses, validate


def test_builtin_and_explicit_all_with_selected_policy_defaults():
    text = '''config firewall policy
    edit 12
        set srcaddr all
        set dstaddr all
    next
    edit 4
        set srcaddr all
        set dstaddr all
        set action accept
        set status disable
    next
end
'''
    config = parse(text)
    assert not validate(config)
    assert not validate(parse(text + 'config firewall address\nedit all\nnext\nend\n'))
    first, second = map(policy_settings, config.policies)
    assert first["action"] == ("deny",)
    assert first["status"] == ("enable",)
    assert first["nat"] == ("disable",)
    assert second["action"] == ("accept",)
    assert second["status"] == ("disable",)
    assert "schedule" not in first


def test_missing_unknown_collision_and_cycle_diagnostics():
    config = parse('''config firewall address
    edit "Sample A"
    next
end
config firewall addrgrp
    edit "Sample A"
        set member nested
    next
    edit nested
        set member all
        set exclude-member "Sample A" "Ghost example"
    next
    edit all
    next
end
config firewall policy
    edit 34
        set status disable
        set srcaddr "sample a" "sample a"
    next
end
''')
    findings = validate(config)
    assert [(f.line, f.code, f.key, f.field, f.reference) for f in findings] == [
        (6, "address-name-collision", "Sample A", None, None),
        (9, "unknown-address-reference", "nested", "exclude-member", "Ghost example"),
        (9, "group-cycle", "nested", "exclude-member", "Sample A"),
        (13, "address-name-collision", "all", None, None),
        (17, "missing-address-list", 34, "dstaddr", None),
        (17, "unknown-address-reference", 34, "srcaddr", "sample a"),
    ]


def test_nested_diamond_does_not_report_a_cycle():
    content = "\n".join(
        f"edit {name}\nset member {members}\nnext"
        for name, members in [("one", "two three"), ("two", "four"),
                              ("three", "four"), ("four", "all")]
    )
    assert not validate(parse(f"config firewall addrgrp\n{content}\nend"))


def test_unused_retains_disabled_refs_orphan_group_members_exclusions_and_opaque_mentions():
    names = ["Z-Inactive", "A-Member", "A-Excluded", "Held Here", "Held Key",
             "Held Field", "Z-Unmentioned", "A-Unmentioned", "all"]
    addresses = "\n".join(f'edit "{name}"\nnext' for name in names)
    config = parse(f'''config firewall address
{addresses}
end
config firewall addrgrp
    edit "Unreferenced group"
        set member A-Member
        set exclude disable
        set exclude-member A-Excluded
    next
end
config firewall policy
    edit 81
        set status disable
        set srcaddr Z-Inactive
        set dstaddr all
        set unmodeled-field "Held Field"
    next
end
config system fictitious
    edit "HELD KEY"
        set object-ref "held here"
        set unrelated "opaque arbitrary value"
    next
end
''')
    result = unused_addresses(config)
    assert result.candidates == ("Z-Unmentioned", "A-Unmentioned")
    assert result.opaque_mentions == ("Held Here", "Held Key", "Held Field")
    assert not result.withheld_reason
    assert "opaque arbitrary value" not in repr(config)


def test_unused_withheld_without_complete_enough_reference_data():
    addresses = "config firewall address\nedit Example\nnext\nend\n"
    broken = "config firewall policy\nedit 9\nset srcaddr Ghost\nset dstaddr all\nnext\nend"
    assert unused_addresses(parse(addresses)).withheld_reason == "missing-policy-section"
    result = unused_addresses(parse(addresses + broken))
    assert result.withheld_reason == "address-reference-findings"
    assert not result.candidates
    assert unused_addresses(parse(addresses + "config firewall policy\nend")).candidates == (
        "Example",
    )
