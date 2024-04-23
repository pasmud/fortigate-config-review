"""Parse reviewed records without interpreting ignored configuration tables."""

import re
from dataclasses import dataclass, field

ADDRESS = ("firewall", "address")
GROUP = ("firewall", "addrgrp")
POLICY = ("firewall", "policy")
FIELDS = {
    ADDRESS: frozenset({"type", "subnet", "start-ip", "end-ip", "fqdn", "wildcard"}),
    GROUP: frozenset({"member", "exclude", "exclude-member"}),
    POLICY: frozenset({
        "name", "status", "action", "srcintf", "dstintf", "srcaddr", "dstaddr",
        "srcaddr-negate", "dstaddr-negate", "schedule", "service", "service-negate",
        "nat", "logtraffic",
    }),
}
TOKEN = re.compile(r'"(?:[^"\\]|\\["\\])*"|[^\s"\\]+')
ESCAPE = re.compile(r'\\(["\\])')
CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
POLICY_ID = re.compile(r"[0-9]{1,10}")


class ParseError(ValueError):
    """The export is outside the supported grammar."""

    def __init__(self, line: int, reason: str):
        self.line = line
        super().__init__(f"line {line}: {reason}")


@dataclass(frozen=True)
class Address:
    name: str
    line: int
    settings: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class Group:
    name: str
    line: int
    settings: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class Policy:
    id: int
    line: int
    settings: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class Config:
    addresses: tuple[Address, ...]
    groups: tuple[Group, ...]
    policies: tuple[Policy, ...]
    has_policy_table: bool
    opaque_address_mentions: frozenset[str] = field(repr=False)


@dataclass
class _Frame:
    kind: str
    line: int
    table: tuple[str, ...] = ()
    key: str | int = ""
    settings: dict[str, tuple[str, ...]] = field(default_factory=dict)
    seen: set[str] = field(default_factory=set)


def _tokens(text: str, line: int) -> tuple[str, ...]:
    tokens = []
    pos = 0
    while pos < len(text):
        if text[pos] in " \t":
            pos += 1
            continue
        match = TOKEN.match(text, pos)
        if not match or (match.end() < len(text) and text[match.end()] not in " \t"):
            raise ParseError(line, "malformed token or quoted string")
        token = match[0]
        tokens.append(ESCAPE.sub(r"\1", token[1:-1]) if token.startswith('"') else token)
        pos = match.end()
    return tuple(tokens)


def parse(text: str) -> Config:
    """Read one root scope. Record order is the order of completed edit blocks."""
    stack: list[_Frame] = []
    seen_tables: set[tuple[str, ...]] = set()
    seen_keys: dict[tuple[str, ...], set[str | int]] = {table: set() for table in FIELDS}
    addresses: list[Address] = []
    groups: list[Group] = []
    policies: list[Policy] = []
    opaque_tokens: set[str] = set()
    for line, raw in enumerate(text.removeprefix("\ufeff").split("\n"), 1):
        raw = raw.removesuffix("\r")
        if CONTROL.search(raw):
            raise ParseError(line, "unexpected control character")
        stripped = raw.strip(" \t")
        if not stripped or stripped.startswith("#"):
            continue
        command, *args = _tokens(stripped, line)
        frame = stack[-1] if stack else None
        table = frame.table if frame else ()
        if command == "config":
            path = tuple(args)
            if not path or not all(path):
                raise ParseError(line, "config requires a section name")
            if path[0] in {"vdom", "global"}:
                raise ParseError(line, "VDOM and global wrappers are outside the root scope")
            if table in FIELDS or (frame and path in FIELDS):
                raise ParseError(line, "reviewed sections must be flat and at the root")
            if path in FIELDS:
                if path in seen_tables:
                    raise ParseError(line, "duplicate reviewed section")
                seen_tables.add(path)
            stack.append(_Frame("config", line, path))
        elif command == "edit":
            if not frame or frame.kind != "config" or len(args) != 1 or not args[0].strip():
                raise ParseError(line, "edit requires one nonblank key inside config")
            key: str | int = args[0]
            if table == POLICY:
                if not POLICY_ID.fullmatch(args[0]) or not 1 <= int(args[0]) <= 4_294_967_294:
                    raise ParseError(line, "policy ID must be an integer from 1 to 4294967294")
                key = int(args[0])
            if table in FIELDS:
                if key in seen_keys[table]:
                    raise ParseError(line, "duplicate record key")
                seen_keys[table].add(key)
            else:
                opaque_tokens.add(args[0].casefold())
            stack.append(_Frame("edit", line, table, key))
        elif command == "next":
            if not frame or frame.kind != "edit" or args:
                raise ParseError(line, "next must close an edit without arguments")
            stack.pop()
            if table == ADDRESS:
                addresses.append(Address(str(frame.key), frame.line, frame.settings))
            elif table == GROUP:
                groups.append(Group(str(frame.key), frame.line, frame.settings))
            elif table == POLICY:
                policies.append(Policy(int(frame.key), frame.line, frame.settings))
        elif command == "end":
            if not frame or frame.kind != "config" or args:
                raise ParseError(line, "end must close a config without arguments")
            stack.pop()
        elif not frame:
            raise ParseError(line, "expected a config section at the root")
        elif table in FIELDS:
            if frame.kind != "edit" or command != "set" or len(args) < 2 or not args[0]:
                raise ParseError(line, "expected set KEY VALUE inside a reviewed edit")
            name, *values = args
            if name in frame.seen:
                raise ParseError(line, "duplicate setting in reviewed edit")
            frame.seen.add(name)
            if name in FIELDS[table]:
                frame.settings[name] = tuple(values)
            else:
                opaque_tokens.update(value.casefold() for value in values)
        elif (
            table == ("system", "global") and command == "set"
            and args[:1] == ["vdom-mode"] and args[1:] != ["no-vdom"]
        ):
            raise ParseError(line, "VDOM mode is outside the root scope")
        else:
            values = args[1:] if command in {"set", "append", "select", "unselect"} else args
            opaque_tokens.update(value.casefold() for value in values)
    if stack:
        raise ParseError(stack[-1].line, f"unclosed {stack[-1].kind} block")
    if not seen_tables:
        raise ParseError(1, "no reviewed section found")
    mentions = frozenset(a.name for a in addresses if a.name.casefold() in opaque_tokens)
    return Config(tuple(addresses), tuple(groups), tuple(policies), POLICY in seen_tables, mentions)
