"""Static heuristics to detect risky SQL concatenations in Java code."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List
import re

SQL_PATTERN = re.compile(r"\b(select|insert|update|delete|call|exec)\b", re.IGNORECASE)
SOURCE_PATTERNS = [
    re.compile(p)
    for p in (
        r"request\.getParameter\s*\(",
        r"request\.getHeader\s*\(",
        r"request\.getQueryString\s*\(",
        r"System\.getenv\s*\(",
        r"System\.getProperty\s*\(",
        r"Scanner\s*\(.*?System\.in",
        r"BufferedReader\s*\(.*?InputStreamReader",
        r"args\s*\[",
    )
]
EXECUTION_PATTERNS = (
    "execute",
    "executeQuery",
    "executeUpdate",
    "executeLargeUpdate",
    "executeBatch",
)
PREPARATION_PATTERNS = (
    "prepareStatement",
    "prepareCall",
)
SANITIZER_PATTERNS = [
    re.compile(r"StringEscapeUtils\.escapeSql"),
    re.compile(r"ESAPI\.encoder\(\)\.encodeForSQL"),
    re.compile(r"sanitizeSql"),
    re.compile(r"SqlUtils\.escape"),
]

IDENTIFIER_RE = re.compile(r"\b[_$A-Za-z][_$0-9A-Za-z]*\b")
STRING_LITERAL_RE = re.compile(r'"(?:\\.|[^"\\])*"')


@dataclass
class Finding:
    """Represents a single SQL injection warning."""

    file: Path
    line: int
    rule_id: str
    message: str
    code: str
    severity: str

    def to_dict(self) -> dict:
        return {
            "file": str(self.file),
            "line": self.line,
            "rule_id": self.rule_id,
            "message": self.message,
            "code": self.code.strip(),
            "severity": self.severity,
        }


class JavaSQLScanner:
    """Very small data-flow tracker tailored for SQL concatenation issues."""

    def __init__(self) -> None:
        self._tainted_vars: set[str] = set()
        self._tainted_builders: set[str] = set()
        self._dangerous_queries: set[str] = set()
        self._sanitized_vars: set[str] = set()
        self._sanitized_queries: set[str] = set()

    def scan_file(self, path: Path) -> List[Finding]:
        self._tainted_vars.clear()
        self._tainted_builders.clear()
        self._dangerous_queries.clear()
        self._sanitized_vars.clear()
        self._sanitized_queries.clear()
        findings: List[Finding] = []

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except FileNotFoundError:
            return findings

        in_block_comment = False
        for line_no, raw_line in enumerate(raw_lines, start=1):
            line, in_block_comment = _strip_comments(raw_line, in_block_comment)
            if not line.strip():
                continue

            normalized = line.strip()
            self._record_sources(normalized)
            self._track_assignments(normalized)
            self._track_builders(normalized)

            if SQL_PATTERN.search(line):
                findings.extend(self._detect_sql_issues(path, line_no, normalized))

            findings.extend(self._detect_preparation_issues(path, line_no, normalized))
            findings.extend(self._detect_execution_issues(path, line_no, normalized))

        return findings

    def _record_sources(self, line: str) -> None:
        # Treat direct uses of input-gathering APIs as taint sources.
        if not any(pattern.search(line) for pattern in SOURCE_PATTERNS):
            return
        target = _lhs_identifier(line)
        if target:
            self._tainted_vars.add(target)
            self._sanitized_vars.discard(target)

    def _track_assignments(self, line: str) -> None:
        assignment = _lhs_identifier(line)
        if not assignment:
            return
        rhs = _rhs_expression(line)
        if not rhs:
            return

        rhs_identifiers = set(IDENTIFIER_RE.findall(rhs))
        sanitized_flag = _is_sanitized(rhs) or (
            rhs_identifiers
            and rhs_identifiers & self._sanitized_vars
            and not rhs_identifiers & self._tainted_vars
        )

        if sanitized_flag:
            self._sanitized_vars.add(assignment)
            self._tainted_vars.discard(assignment)
        else:
            self._sanitized_vars.discard(assignment)
            self._sanitized_queries.discard(assignment)

        if rhs_identifiers & self._tainted_vars:
            self._tainted_vars.add(assignment)
        elif assignment in self._tainted_vars and not sanitized_flag:
            self._tainted_vars.discard(assignment)

        if rhs_identifiers & self._dangerous_queries:
            self._dangerous_queries.add(assignment)
            if rhs_identifiers & self._sanitized_queries and not rhs_identifiers & self._tainted_vars:
                self._sanitized_queries.add(assignment)

        if _contains_sql_string(rhs):
            if "+" in rhs or self._tainted_vars & rhs_identifiers or rhs_identifiers & self._dangerous_queries:
                self._dangerous_queries.add(assignment)
                if sanitized_flag:
                    self._sanitized_queries.add(assignment)
                else:
                    self._sanitized_queries.discard(assignment)

    def _track_builders(self, line: str) -> None:
        builder_match = re.search(r"StringBuilder\s+(\w+)", line)
        if builder_match:
            self._tainted_builders.add(builder_match.group(1))
            return
        append_match = re.search(r"(\w+)\.append\((.+)\)", line)
        if append_match:
            name, arg = append_match.groups()
            if name in self._tainted_builders and (
                "+" in arg or any(var in self._tainted_vars for var in IDENTIFIER_RE.findall(arg))
            ):
                self._dangerous_queries.add(name)
                arg_identifiers = set(IDENTIFIER_RE.findall(arg))
                if arg_identifiers & self._sanitized_vars and not arg_identifiers & self._tainted_vars:
                    self._sanitized_queries.add(name)
                else:
                    self._sanitized_queries.discard(name)

    def _detect_sql_issues(self, path: Path, line_no: int, line: str) -> List[Finding]:
        findings: List[Finding] = []
        if not (
            "+" in line
            or "String.format" in line
            or any(var in line for var in self._tainted_vars)
        ):
            return findings

        if _is_safe_parameterized(line):
            return findings

        severity = "medium"
        if self._uses_sanitization(line):
            severity = "low"

        findings.append(
            Finding(
                file=path,
                line=line_no,
                rule_id="SQL001",
                message="SQL string built with dynamic input",
                code=line.strip(),
                severity=severity,
            )
        )
        return findings

    def _detect_execution_issues(self, path: Path, line_no: int, line: str) -> List[Finding]:
        findings: List[Finding] = []
        if not any(f".{call}(" in line for call in EXECUTION_PATTERNS):
            return findings

        query_arg = _extract_first_argument(line)
        if not query_arg:
            return findings
        rhs_identifiers = set(IDENTIFIER_RE.findall(query_arg))

        suspicious = False
        if rhs_identifiers & self._dangerous_queries:
            suspicious = True
        elif rhs_identifiers & self._tainted_vars:
            suspicious = True
        elif "+" in query_arg and _contains_sql_string(query_arg):
            suspicious = True

        if not suspicious:
            return findings

        severity = "high"
        if self._uses_sanitization(query_arg) or rhs_identifiers & self._sanitized_queries:
            severity = "medium"

        findings.append(
            Finding(
                file=path,
                line=line_no,
                rule_id="SQL002",
                message="Executing SQL built from user-influenced data",
                code=line.strip(),
                severity=severity,
            )
        )
        return findings

    def _detect_preparation_issues(self, path: Path, line_no: int, line: str) -> List[Finding]:
        findings: List[Finding] = []
        if not any(f".{call}(" in line for call in PREPARATION_PATTERNS):
            return findings

        query_arg = _extract_first_argument(line)
        if not query_arg:
            return findings

        rhs_identifiers = set(IDENTIFIER_RE.findall(query_arg))
        suspicious = False

        if rhs_identifiers & self._dangerous_queries:
            suspicious = True
        elif rhs_identifiers & self._tainted_vars:
            suspicious = True
        elif "+" in query_arg and _contains_sql_string(query_arg):
            suspicious = True

        if not suspicious:
            return findings

        severity = "medium"
        if self._uses_sanitization(query_arg) or rhs_identifiers & self._sanitized_queries:
            severity = "low"

        findings.append(
            Finding(
                file=path,
                line=line_no,
                rule_id="SQL003",
                message="Prepared/Callable statement built from user data",
                code=line.strip(),
                severity=severity,
            )
        )
        return findings

    def _uses_sanitization(self, text: str) -> bool:
        if _is_sanitized(text):
            return True
        for symbol in self._sanitized_vars | self._sanitized_queries:
            if _contains_symbol(text, symbol):
                return True
        return False


def scan_path(path: Path | str) -> List[Finding]:
    """Scan a file or directory and return all findings."""

    root = Path(path)
    scanner = JavaSQLScanner()
    paths: Iterable[Path]
    if root.is_file():
        paths = [root]
    else:
        paths = root.rglob("*.java")

    findings: List[Finding] = []
    for java_file in paths:
        findings.extend(scanner.scan_file(java_file))
    return findings


def scan_source(source: str, path: str = "Sample.java") -> List[Finding]:
    """Convenience helper for unit tests."""

    tmp_path = Path(path)
    scanner = JavaSQLScanner()
    findings: List[Finding] = []
    in_block_comment = False
    for idx, raw in enumerate(source.splitlines(), start=1):
        line, in_block_comment = _strip_comments(raw, in_block_comment)
        if not line.strip():
            continue
        stmt = line.strip()
        scanner._record_sources(stmt)
        scanner._track_assignments(stmt)
        scanner._track_builders(stmt)
        if SQL_PATTERN.search(line):
            findings.extend(scanner._detect_sql_issues(tmp_path, idx, stmt))
        findings.extend(scanner._detect_preparation_issues(tmp_path, idx, stmt))
        findings.extend(scanner._detect_execution_issues(tmp_path, idx, stmt))
    return findings


def _strip_comments(line: str, in_block: bool) -> tuple[str, bool]:
    result = []
    i = 0
    while i < len(line):
        if not in_block and line.startswith("/*", i):
            in_block = True
            i += 2
            continue
        if in_block and line.startswith("*/", i):
            in_block = False
            i += 2
            continue
        if not in_block and line.startswith("//", i):
            break
        result.append(line[i])
        i += 1
    return ("".join(result), in_block)


def _lhs_identifier(line: str) -> str | None:
    if "=" not in line:
        return None
    left = line.split("=", 1)[0].strip()
    parts = IDENTIFIER_RE.findall(left)
    if not parts:
        return None
    return parts[-1]


def _rhs_expression(line: str) -> str | None:
    if "=" not in line:
        return None
    right = line.split("=", 1)[1]
    if ";" in right:
        right = right.split(";", 1)[0]
    return right.strip()


def _contains_sql_string(expr: str) -> bool:
    return any(SQL_PATTERN.search(match.group()) for match in STRING_LITERAL_RE.finditer(expr))


def _is_safe_parameterized(line: str) -> bool:
    return "?" in line and "+" not in line


def _extract_first_argument(line: str) -> str | None:
    start = line.find("(")
    if start == -1:
        return None
    depth = 0
    arg_chars: List[str] = []
    for ch in line[start + 1 :]:
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                break
            depth -= 1
        arg_chars.append(ch)
    if not arg_chars:
        return None
    return "".join(arg_chars).strip()


def _is_sanitized(expr: str) -> bool:
    return any(pattern.search(expr) for pattern in SANITIZER_PATTERNS)


def _contains_symbol(text: str, symbol: str) -> bool:
    return bool(re.search(rf"\b{re.escape(symbol)}\b", text))
