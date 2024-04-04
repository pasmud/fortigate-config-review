import pytest

from fortigate_review.parser import ParseError, parse


def test_records_and_order_with_quoted_values_and_opaque_nesting():
    config = parse(r'''
# fictional backup
config system fictitious
    edit "ignored"
        config nested
            set private-value "never retained"
        end
    next
end
config firewall address
    edit "Lab \"A\" \\ desk"
        set subnet 192.0.2.0 255.255.255.0
        set comment ""
    next
end
config firewall addrgrp
    edit "Lab set"
        set member "Lab \"A\" \\ desk" all
    next
end
config firewall policy
    edit 91
        set name "Lab rule"
        set srcaddr "Lab set"
    next
    edit 4
    next
end
''')
    assert config.addresses[0].name == 'Lab "A" \\ desk'
    assert config.addresses[0].settings == {"subnet": ("192.0.2.0", "255.255.255.0")}
    assert config.groups[0].settings["member"] == (config.addresses[0].name, "all")
    assert [policy.id for policy in config.policies] == [91, 4]
    assert config.policies[0].line == 22


def test_bom_crlf_and_empty_reviewed_section():
    assert parse("\ufeffconfig firewall policy\r\nend\r\n").policies == ()


@pytest.mark.parametrize(("text", "error"), [
    ("", "no reviewed section"),
    ("config firewall policy\nedit 11\nend", "line 3: end"),
    ("config firewall policy\nedit 11", "line 2: unclosed edit"),
    ("config firewall policy\nedit 0", "policy ID"),
    ("config firewall policy\nedit 5\nnext\nedit 05", "duplicate record"),
    ("config firewall policy\nend\nconfig firewall policy", "duplicate reviewed"),
    ('config firewall address\nedit "unclosed', "malformed token"),
    ('config firewall address\nedit "a"b', "malformed token"),
    ("config firewall address\nedit a\nset type fqdn\nset type ipmask", "duplicate setting"),
    ("config firewall address\nedit a\nunset type", "expected set"),
    ("config vdom", "outside the root scope"),
    ("config global", "outside the root scope"),
    ("config system global\nset vdom-mode multi-vdom", "outside the root scope"),
    ("config system fiction\nconfig firewall policy", "at the root"),
    ("config firewall policy\nedit 7\nconfig nested", "must be flat"),
])
def test_rejects_ambiguous_or_unsupported_exports(text, error):
    with pytest.raises(ParseError, match=error):
        parse(text)
