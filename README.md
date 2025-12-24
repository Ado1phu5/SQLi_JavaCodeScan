# SQLi_JavaCodeScan

A lightweight, efficient, and verifiable static analysis helper that highlights risky SQL concatenation patterns in Java projects. The tool intentionally favors a simple heuristic-driven design so it can run anywhere without heavyweight dependencies, yet still provide actionable findings you can manually verify.

## Features

- Detects SQL strings built with string concatenation, `String.format`, or tainted `StringBuilder` chains.
- Tracks a small data-flow set of common request/input sources to reduce noise.
- Flags execution sites (`Statement.execute*`) and prepared statements that reference unsafe query variables.
- Severity column (high/medium/low) plus sanitizer awareness helps prioritize fixes.
- CLI offers human-readable tables or JSON for tooling integration.
- Comes with pytest coverage for the most critical behaviors so you can verify logic changes quickly.

## Getting Started

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The requirements file installs the package in editable mode and bundles pytest so CLI entry points and tests stay in sync with the source tree.

Then run a scan (defaults to the current directory):

```bash
sqliaudit src/
```

Use JSON output (great for CI annotations):

```bash
sqliaudit src/ --format json
```

Fail builds when any findings are present:

```bash
sqliaudit src/ --fail-on-findings
```

## Verification Samples

The `samples/` directory contains ready-to-scan Java snippets that exercise the detector:

- `samples/vulnerable/ClassicConcat.java` – classic string concatenation detected as `SQL001/SQL002 (high)`.
- `samples/vulnerable/UnsafePrepared.java` – misuse of `prepareStatement` triggers `SQL003`.
- `samples/safe/SanitizedQuery.java` – escaping lowers severity to `low`.
- `samples/safe/Parameterized.java` – proper prepared statement produces zero findings.

Run the scanner over the vulnerable set:

```bash
sqliaudit samples/vulnerable
```

And compare with the safe set:

```bash
sqliaudit samples/safe
```

## Development

Run the unit test suite before publishing changes:

```bash
pytest
```

The scanner lives in `src/sqliaudit/scanner.py`, while the CLI entry point is `src/sqliaudit/cli.py`. Tests use the `scan_source` helper for fast verification without touching the filesystem.
