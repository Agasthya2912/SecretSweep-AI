"""
obfuscation/concat_reassembler.py

Detects secrets split across multiple lines or variables — direct
concatenation (a + b), f-string assembly, "".join(...) on a list, and
+= accumulation — and reassembles them into the full value so
PatternScanner can recognize what a single line's regex never would.
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from scanner.models import DiffLine
from scanner.pattern_scanner import PatternScanner

# var = "literal"  (single or double quotes; rejects "".join(...) via the
# negative lookahead so an empty-string-literal method call isn't mistaken
# for an assignment of "").
_ASSIGNMENT_RE = re.compile(r"""(\w+)\s*=\s*(["'])((?:(?!\2).)*)\2(?!\s*\.\w)""")

# var += "chunk"
_PLUS_EQUALS_RE = re.compile(r"""(\w+)\s*\+=\s*(["'])((?:(?!\2).)*)\2""")

# var = a + b (+ c ...)   — bare identifiers only, no leading quote
_CONCAT_RE = re.compile(r"(\w+)\s*=\s*(\w+(?:\s*\+\s*\w+)+)\s*$")

# var = f"...{a}...{b}..."
_FSTRING_RE = re.compile(r"""(\w+)\s*=\s*f(["'])((?:(?!\2).)*)\2""")
_FSTRING_VAR_RE = re.compile(r"\{(\w+)\}")

# var = [ "a", "b", "c" ]
_LIST_LITERAL_RE = re.compile(r"(\w+)\s*=\s*\[(.*?)\]")

# var = "".join([...])   (inline list literal)
_JOIN_INLINE_RE = re.compile(r"""(\w+)\s*=\s*(["'])\2\.join\(\s*\[(.*?)\]\s*\)""")

# var = "".join(list_var)  (reference to a previously-assigned list)
_JOIN_VAR_RE = re.compile(r"""(\w+)\s*=\s*(["'])\2\.join\(\s*(\w+)\s*\)""")

_QUOTED_ITEM_RE = re.compile(r"""(["'])((?:(?!\1).)*)\1""")

# Reassembly confidence is derived from the underlying PatternMatch's confidence,
# scaled down to reflect that cross-line reassembly is a heuristic, not a direct hit.
_REASSEMBLY_CONFIDENCE_SCALE = 0.9


@dataclass
class ReassembledSecret:
    """A secret whose value only exists once its scattered components are joined."""

    components: List[str] = field(default_factory=list)  # the parts that were joined
    reassembled_value: str = ""  # the full reassembled string
    reassembled_hash: str = ""  # SHA256 of reassembled value — never store the raw value
    pattern_name: str = ""  # what secret type it matched
    severity_hint: str = ""
    lines_involved: List[int] = field(default_factory=list)  # line numbers of components
    confidence: float = 0.0


def _extract_list_items(bracket_body: str) -> List[str]:
    return [match.group(2) for match in _QUOTED_ITEM_RE.finditer(bracket_body)]


class ConcatReassembler:
    """Finds secrets split across variables via +, f-strings, .join(), or +=."""

    def __init__(self) -> None:
        self._pattern_scanner = PatternScanner()

    def extract_string_assignments(self, lines: List[DiffLine]) -> Dict[str, str]:
        """Scan lines for `variable = "string"` assignments (either quote style).

        Later assignments to the same variable name overwrite earlier ones, matching
        how the value would actually change as execution reaches each line in order.
        """
        assignments: Dict[str, str] = {}
        for line in lines:
            for match in _ASSIGNMENT_RE.finditer(line.content):
                var_name, _quote, value = match.groups()
                assignments[var_name] = value
        return assignments

    def find_concatenations(
        self, lines: List[DiffLine], assignments: Dict[str, str]
    ) -> List[ReassembledSecret]:
        """Walk lines in order, resolving +, f-string, .join(), and += patterns
        against known variable values, and check each reassembled result against
        PatternScanner (wrapped back into `result_var = "value"` form so both
        provider-specific and generic keyword-based patterns can apply).
        """
        working = dict(assignments)
        contributing_lines: Dict[str, List[int]] = {}
        list_literals: Dict[str, List[str]] = {}
        results: List[ReassembledSecret] = []

        for line in lines:
            content = line.content

            plus_equals_match = _PLUS_EQUALS_RE.search(content)
            if plus_equals_match:
                var, _quote, chunk = plus_equals_match.groups()
                working[var] = working.get(var, "") + chunk
                contributing_lines.setdefault(var, []).append(line.line_number)
                self._emit_if_secret(
                    results,
                    result_var=var,
                    components=[chunk],  # only this line's own contribution
                    reassembled=working[var],
                    lines_involved=list(contributing_lines[var]),
                )
                continue

            assignment_match = _ASSIGNMENT_RE.search(content)
            if assignment_match:
                var, _quote, value = assignment_match.groups()
                working[var] = value
                contributing_lines[var] = [line.line_number]

            list_match = _LIST_LITERAL_RE.search(content)
            if list_match:
                var, body = list_match.groups()
                list_literals[var] = _extract_list_items(body)
                contributing_lines[var] = [line.line_number]

            join_inline_match = _JOIN_INLINE_RE.search(content)
            if join_inline_match:
                result_var, _quote, body = join_inline_match.groups()
                items = _extract_list_items(body)
                reassembled = "".join(items)
                self._emit_if_secret(
                    results,
                    result_var=result_var,
                    components=items,
                    reassembled=reassembled,
                    lines_involved=[line.line_number],
                )
                continue

            join_var_match = _JOIN_VAR_RE.search(content)
            if join_var_match:
                result_var, _quote, list_var = join_var_match.groups()
                items = list_literals.get(list_var)
                if items:
                    reassembled = "".join(items)
                    lines_involved = sorted(
                        set(contributing_lines.get(list_var, []) + [line.line_number])
                    )
                    self._emit_if_secret(
                        results,
                        result_var=result_var,
                        components=items,
                        reassembled=reassembled,
                        lines_involved=lines_involved,
                    )
                continue

            fstring_match = _FSTRING_RE.search(content)
            if fstring_match:
                result_var, _quote, template = fstring_match.groups()
                var_names = _FSTRING_VAR_RE.findall(template)
                if var_names and all(v in working for v in var_names):
                    reassembled = _FSTRING_VAR_RE.sub(lambda m: working[m.group(1)], template)
                    components = [working[v] for v in var_names]
                    lines_involved = sorted(
                        set(
                            sum((contributing_lines.get(v, []) for v in var_names), [])
                            + [line.line_number]
                        )
                    )
                    self._emit_if_secret(
                        results,
                        result_var=result_var,
                        components=components,
                        reassembled=reassembled,
                        lines_involved=lines_involved,
                    )
                continue

            concat_match = _CONCAT_RE.search(content)
            if concat_match:
                result_var, expr = concat_match.groups()
                parts = [p.strip() for p in expr.split("+")]
                if parts and all(p in working for p in parts):
                    components = [working[p] for p in parts]
                    reassembled = "".join(components)
                    lines_involved = sorted(
                        set(
                            sum((contributing_lines.get(p, []) for p in parts), [])
                            + [line.line_number]
                        )
                    )
                    self._emit_if_secret(
                        results,
                        result_var=result_var,
                        components=components,
                        reassembled=reassembled,
                        lines_involved=lines_involved,
                    )
                continue

        return results

    def scan(self, lines: List[DiffLine]) -> List[ReassembledSecret]:
        """Extract assignments, then look for concatenation patterns built from them."""
        assignments = self.extract_string_assignments(lines)
        return self.find_concatenations(lines, assignments)

    def _emit_if_secret(
        self,
        results: List[ReassembledSecret],
        result_var: str,
        components: List[str],
        reassembled: str,
        lines_involved: List[int],
    ) -> None:
        """Re-check the reassembled value with PatternScanner; append a ReassembledSecret
        only if it actually matches a known secret pattern.

        Wrapping as `result_var = "value"` (rather than scanning the bare value) lets
        both provider-specific patterns (which match on value shape alone) and generic
        keyword patterns (api_key=/secret=/token=/password=, which need the variable
        name context) fire correctly.
        """
        if not reassembled:
            return

        synthetic_line = DiffLine(
            file_path="<reassembled>",
            line_number=lines_involved[0] if lines_involved else 0,
            content=f'{result_var} = "{reassembled}"',
            change_type="added",
            commit_hash="",
            author_email="",
        )
        matches = self._pattern_scanner.scan_line(synthetic_line)
        if not matches:
            return

        best = matches[0]
        results.append(
            ReassembledSecret(
                components=components,
                reassembled_value=reassembled,
                reassembled_hash=hashlib.sha256(reassembled.encode("utf-8")).hexdigest(),
                pattern_name=best.pattern_name,
                severity_hint=best.severity_hint,
                lines_involved=sorted(set(lines_involved)),
                confidence=round(best.confidence * _REASSEMBLY_CONFIDENCE_SCALE, 2),
            )
        )
