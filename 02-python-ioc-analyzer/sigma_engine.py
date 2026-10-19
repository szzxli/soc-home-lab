#!/usr/bin/env python3
"""Sigma rule engine — match log records against Sigma detection rules.

Implements a deliberately small subset of the open Sigma rule format
(SigmaHQ specification): rule *parsing* is delegated to the ``pysigma``
library; this module adds the *matching* layer that evaluates a parsed
rule's ``detection`` section against plain Python dict log records.

Supported subset
----------------
- ``detection`` selections with field/value items; value lists are OR-ed,
  items inside one selection are AND-ed (per the Sigma spec defaults).
- Field modifiers: ``contains``, ``startswith``, ``endswith``,
  ``windash``, ``re`` (regular expression). Matching is case-insensitive
  unless the ``cased`` modifier is used.
- Value types: strings (with ``*``/``?`` wildcards), numbers, booleans,
  ``null``, CIDR expressions, ``exists`` checks.
- Conditions: ``and`` / ``or`` / ``not``, parentheses, bare identifiers,
  ``1 of <pattern>`` / ``all of <pattern>`` (``them`` or ``name*`` prefix).
- Nested field access with dot notation (``responseElements.ConsoleLogin``).

Explicitly NOT supported (rule is skipped with a warning, never crashes):
``base64``/``base64offset``/``utf16`` encodings, ``expand`` placeholders,
``near`` temporal correlation, aggregation conditions (``count() by``).

Findings use the same dict shape as ``ioc_analyzer.py`` so both detectors
can feed one report. The ``rule_id``/``rule_title`` keys identify the
Sigma rule that fired.

Usage:
    from sigma_engine import load_rules, scan_records
    rules, problems = load_rules("rules")
    findings = scan_records(rules, records)
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from sigma.collection import SigmaCollection
    from sigma.conditions import ConditionAND, ConditionOR
    from sigma.types import (
        SigmaBool,
        SigmaCasedString,
        SigmaCIDRExpression,
        SigmaExists,
        SigmaNull,
        SigmaNumber,
        SigmaRegularExpression,
        SigmaString,
        SpecialChars,
    )

    _PYSIGMA_AVAILABLE = True
except ImportError:  # pragma: no cover - handled gracefully by callers
    _PYSIGMA_AVAILABLE = False


def load_rules(rules_dir: str) -> Tuple[List[Any], List[str]]:
    """Load ``*.yml``/``*.yaml`` Sigma rules from *rules_dir*.

    Returns ``(rules, problems)``: parsed ``SigmaRule`` objects and a list
    of human-readable warnings for files that failed to parse (a bad rule
    never aborts the whole load).
    """
    rules: List[Any] = []
    problems: List[str] = []
    if not _PYSIGMA_AVAILABLE:
        return rules, ["pysigma is not installed; Sigma scanning disabled"]
    directory = Path(rules_dir)
    if not directory.is_dir():
        return rules, [f"rules directory not found: {rules_dir}"]
    paths = sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml"))
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
            collection = SigmaCollection.from_yaml(text)
        except Exception as exc:  # malformed YAML or invalid rule
            problems.append(f"{path.name}: skipped ({exc})")
            continue
        for rule in collection.rules:
            rules.append(rule)
    return rules, problems

# ---------------------------------------------------------------------------
# Value matching
# ---------------------------------------------------------------------------


class _Unsupported(Exception):
    """Raised for Sigma features outside this engine's supported subset."""


def _sigma_string_to_regex(value: SigmaString) -> str:
    """Convert a parsed SigmaString (with wildcard markers) to a regex."""
    parts: List[str] = []
    for part in value.s:
        if part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            parts.append(re.escape(str(part)))
    return "".join(parts)


def _lookup_field(record: Dict[str, Any], field: Optional[str]) -> Tuple[bool, Any]:
    """Resolve a (possibly dotted) field name against a record dict."""
    if not field:
        return False, None
    current: Any = record
    for chunk in field.split("."):
        if isinstance(current, dict) and chunk in current:
            current = current[chunk]
        else:
            return False, None
    return True, current


def _match_value(
    sigma_value: Any, record_value: Any, case_sensitive: bool, windash: bool
) -> bool:
    """Match one Sigma value against one record value."""
    if isinstance(sigma_value, SigmaNull):
        return record_value is None
    if isinstance(sigma_value, SigmaExists):
        present = record_value is not None
        return present if sigma_value.exists else not present
    if record_value is None:
        return False
    if isinstance(sigma_value, SigmaBool):
        return bool(record_value) is sigma_value.boolean
    if isinstance(sigma_value, SigmaNumber):
        try:
            return float(record_value) == float(sigma_value.number)
        except (TypeError, ValueError):
            return False
    if isinstance(sigma_value, SigmaCIDRExpression):
        try:
            net = ipaddress.ip_network(str(sigma_value), strict=False)
            return ipaddress.ip_address(str(record_value)) in net
        except ValueError:
            return False
    if isinstance(sigma_value, SigmaRegularExpression):
        try:
            return re.search(sigma_value.regexp, str(record_value)) is not None
        except re.error:
            return False
    if isinstance(sigma_value, SigmaString):
        pattern = _sigma_string_to_regex(sigma_value)
        flags = 0 if case_sensitive else re.IGNORECASE
        candidates = [str(record_value)]
        if windash:
            # |windash: a leading "-" also matches "/" and vice versa.
            swapped = re.sub(
                r"(^|\s)[-/]",
                lambda m: m.group(1) + ("/" if m.group(2) == "-" else "-"),
                str(record_value),
            )
            candidates.append(swapped)
        try:
            return any(
                re.search(pattern, cand, flags) is not None for cand in candidates
            )
        except re.error:
            return False
    raise _Unsupported(f"value type {type(sigma_value).__name__}")


_UNSUPPORTED_MODIFIERS = {
    "SigmaBase64Modifier",
    "SigmaBase64OffsetModifier",
    "SigmaUTF16Modifier",
    "SigmaUTF16BEModifier",
    "SigmaWideModifier",
    "SigmaExpandModifier",
    "SigmaFieldReferenceModifier",
    "SigmaCIDRModifier",
}


def _match_item(item: Any, record: Dict[str, Any]) -> bool:
    """Evaluate one SigmaDetectionItem against a record."""
    nested = getattr(item, "detection", None)
    if nested is not None:  # nested detection block
        result = _match_detection(nested, record)
        return (not result) if item.negated else result

    # NOTE: pysigma stores modifier *classes* (not instances) here.
    modifiers = {getattr(m, "__name__", type(m).__name__) for m in item.modifiers}
    if modifiers & _UNSUPPORTED_MODIFIERS:
        raise _Unsupported(f"modifiers {sorted(modifiers & _UNSUPPORTED_MODIFIERS)}")

    case_sensitive = "SigmaCaseSensitiveModifier" in modifiers or any(
        isinstance(v, SigmaCasedString) for v in item.value
    )
    windash = "SigmaWindowsDashModifier" in modifiers

    found, record_value = _lookup_field(record, item.field)
    if not found:
        # Only null/exists checks can match a missing field.
        record_value = None

    value_linking = getattr(item, "value_linking", None)
    match_any = value_linking is None or (
        _PYSIGMA_AVAILABLE and value_linking is ConditionOR
    )

    results = [
        _match_value(v, record_value, case_sensitive, windash) for v in item.value
    ]
    if not results:  # e.g. empty value list
        combined = False
    elif match_any:
        combined = any(results)
    else:
        combined = all(results)
    return (not combined) if item.negated else combined


def _match_detection(detection: Any, record: Dict[str, Any]) -> bool:
    """Evaluate one named SigmaDetection (AND/OR of its items)."""
    items = list(detection.detection_items)
    if not items:
        return False
    item_linking = getattr(detection, "item_linking", None)
    results = [_match_item(item, record) for item in items]
    if _PYSIGMA_AVAILABLE and item_linking is ConditionOR:
        return any(results)
    return all(results)  # Sigma default: AND

# ---------------------------------------------------------------------------
# Condition parsing ("selection and not filter", "1 of sel*", ...)
# ---------------------------------------------------------------------------


def _tokenize(condition: str) -> List[str]:
    tokens: List[str] = []
    i = 0
    while i < len(condition):
        ch = condition[i]
        if ch.isspace():
            i += 1
        elif ch in "()":
            tokens.append(ch)
            i += 1
        else:
            j = i
            while j < len(condition) and not condition[j].isspace() and condition[j] not in "()":
                j += 1
            tokens.append(condition[i:j])
            i = j
    return tokens


class _ConditionParser:
    """Recursive-descent parser for Sigma condition expressions."""

    def __init__(self, tokens: List[str], results: Dict[str, bool]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.results = results

    def peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> str:
        tok = self.peek()
        if tok is None:
            raise _Unsupported("unexpected end of condition")
        self.pos += 1
        return tok

    def parse(self) -> bool:
        value = self._parse_or()
        if self.peek() is not None:
            raise _Unsupported(f"trailing tokens in condition: {self.peek()}")
        return value

    def _parse_or(self) -> bool:
        value = self._parse_and()
        while (tok := self.peek()) is not None and tok.lower() == "or":
            self.next()
            # NOTE: parse the right side unconditionally — short-circuiting
            # here would leave tokens unconsumed and break `parse()`.
            rhs = self._parse_and()
            value = value or rhs
        return value

    def _parse_and(self) -> bool:
        value = self._parse_not()
        while (tok := self.peek()) is not None and tok.lower() == "and":
            self.next()
            rhs = self._parse_not()
            value = value and rhs
        return value

    def _parse_not(self) -> bool:
        if (tok := self.peek()) is not None and tok.lower() == "not":
            self.next()
            return not self._parse_not()
        return self._parse_primary()

    def _parse_primary(self) -> bool:
        tok = self.next()
        if tok == "(":
            value = self._parse_or()
            if self.next() != ")":
                raise _Unsupported("unbalanced parenthesis in condition")
            return value
        low = tok.lower()
        if low in ("1", "all"):
            # "1 of <pattern>" / "all of <pattern>"
            if (self.next() or "").lower() != "of":
                raise _Unsupported(f"expected 'of' after '{tok}'")
            pattern = self.next()
            names = self._expand_pattern(pattern)
            if low == "1":
                return any(self.results.get(n, False) for n in names)
            return all(self.results.get(n, False) for n in names) and bool(names)
        # bare detection identifier
        if tok not in self.results:
            raise _Unsupported(f"unknown detection identifier '{tok}'")
        return self.results[tok]

    def _expand_pattern(self, pattern: str) -> List[str]:
        if pattern == "them":
            return list(self.results)
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return [n for n in self.results if n.startswith(prefix)]
        if pattern in self.results:
            return [pattern]
        raise _Unsupported(f"unknown detection pattern '{pattern}'")


def _evaluate_condition(condition: str, results: Dict[str, bool]) -> bool:
    return _ConditionParser(_tokenize(condition), results).parse()


def _record_actor(record: Dict[str, Any]) -> str:
    """Best-effort principal name for a generic log record."""
    if record.get("userName"):
        return str(record["userName"])
    identity = record.get("userIdentity")
    if isinstance(identity, dict):
        for key in ("userName", "principalId", "arn"):
            if identity.get(key):
                return str(identity[key])
    return "unknown"


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

_LEVEL_TO_RISK = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


def rule_matches(rule: Any, record: Dict[str, Any]) -> bool:
    """Evaluate a parsed SigmaRule's detection section against one record."""
    detection = rule.detection
    detections = detection.detections
    results: Dict[str, bool] = {}
    for name, det in detections.items():
        results[name] = _match_detection(det, record)
    conditions = detection.condition
    if not conditions:
        # No explicit condition: a single selection must match.
        if len(results) == 1:
            return next(iter(results.values()))
        raise _Unsupported("multi-selection rule without condition")
    return any(_evaluate_condition(str(c), results) for c in conditions)


def scan_records(
    rules: List[Any], records: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Run *rules* over *records*; return ``(findings, problems)``.

    Findings use the same dict shape as ``ioc_analyzer.detect_all`` with
    ``detector="sigma"`` plus ``rule_id``/``rule_title``. Rules that use
    unsupported features are skipped (reported in *problems*), never crash
    the scan.
    """
    findings: List[Dict[str, Any]] = []
    problems: List[str] = []
    skipped_rules: set = set()
    for rule in rules:
        title = str(getattr(rule, "title", "unnamed"))
        for record in records:
            try:
                matched = rule_matches(rule, record)
            except _Unsupported as exc:
                if title not in skipped_rules:
                    problems.append(f"rule '{title}': skipped ({exc})")
                    skipped_rules.add(title)
                break
            except Exception as exc:  # defensive: one bad record can't kill a scan
                problems.append(f"rule '{title}': error on record ({exc})")
                continue
            if not matched:
                continue
            level = str(getattr(rule, "level", "medium") or "medium").lower()
            findings.append(
                {
                    "detector": "sigma",
                    "rule_id": str(getattr(rule, "id", "n/a")),
                    "rule_title": title,
                    "time": record.get("eventTime")
                    or record.get("timestamp")
                    or "unknown",
                    "event": str(
                        record.get("eventName")
                        or record.get("EventID")
                        or record.get("event_type")
                        or "unknown"
                    ),
                    "actor": _record_actor(record),
                    "ip": str(
                        record.get("sourceIPAddress")
                        or record.get("IpAddress")
                        or "n/a"
                    ),
                    "risk": _LEVEL_TO_RISK.get(level, "medium"),
                    "evidence": (
                        f"Sigma rule '{title}' matched "
                        f"(id={getattr(rule, 'id', 'n/a')}, "
                        f"level={level})."
                    ),
                }
            )
    findings.sort(key=lambda f: str(f.get("time")))
    return findings, problems
