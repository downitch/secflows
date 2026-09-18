#!/usr/bin/env python3
"""
sast_triage.py

Consolidates SARIF output from multiple SAST tools (Semgrep, CodeQL, ...)
into a single triage report. Findings that overlap in the same file/line
range across tools are grouped as "confirmed by multiple tools", which is
treated as a confidence signal.

Modes:
  --mode report-only   Always exits 0. Produces the report for human review.
  --mode enforce        Same report, but the process exits non-zero if any
                        finding is classified BLOCK. Callers should run this
                        step with `continue-on-error` or capture the exit
                        code manually, since the report should still be
                        posted/uploaded even when the gate fails.

This script makes the classification call automatically; it does NOT decide
whether a finding is a true or false positive. That distinction still
requires a human to look at the flagged file and confirm reachability from
an untrusted input. See DECISIONS.md for where this tool is trusted and
where it is deliberately not.
"""

import argparse
import glob
import json
import sys
from pathlib import Path

SEVERITY_RANK = {"error": 3, "warning": 2, "note": 1, "none": 0}
VERDICT_TO_LEVEL = {"BLOCK": "error", "WARN": "warning", "ASYNC": "note"}
ICONS = {"BLOCK": "\U0001F6AB", "WARN": "\u26A0\uFE0F", "ASYNC": "\U0001F553"}


def load_sarif_findings(path):
    """Parse one SARIF file into a flat list of normalized finding dicts."""
    findings = []
    try:
        data = json.loads(Path(path).read_text())
    except (json.JSONDecodeError, OSError) as exc:
        print(f"::warning::Could not parse {path}: {exc}", file=sys.stderr)
        return findings

    for run in data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")

        rules_index = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            rules_index[rule.get("id")] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules_index.get(rule_id, {})
            rule_props = rule.get("properties", {}) or {}
            result_props = result.get("properties", {}) or {}

            level = (
                result.get("level")
                or rule.get("defaultConfiguration", {}).get("level")
                or "warning"
            )

            security_severity = result_props.get("security-severity") or rule_props.get(
                "security-severity"
            )
            try:
                security_severity = float(security_severity) if security_severity else None
            except (TypeError, ValueError):
                security_severity = None

            confidence = (
                result_props.get("confidence") or rule_props.get("confidence") or "MEDIUM"
            )
            confidence = str(confidence).upper()

            message = result.get("message", {}).get("text", "").strip()
            locations = result.get("locations") or [{}]

            for loc in locations:
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "unknown")
                region = phys.get("region", {}) or {}
                start = region.get("startLine")
                end = region.get("endLine", start)

                findings.append(
                    {
                        "tool": tool_name,
                        "rule_id": rule_id,
                        "level": level,
                        "security_severity": security_severity,
                        "confidence": confidence,
                        "file": uri,
                        "start_line": start,
                        "end_line": end,
                        "message": message,
                    }
                )
    return findings


def classify(finding, thresholds):
    """Map one finding to BLOCK / WARN / ASYNC using severity + confidence."""
    rank = SEVERITY_RANK.get(finding["level"], 1)
    sec_sev = finding["security_severity"]
    confidence = finding["confidence"]

    if sec_sev is not None:
        if sec_sev >= thresholds["block_min_score"]:
            rank = max(rank, SEVERITY_RANK["error"])
        elif sec_sev >= thresholds["warn_min_score"]:
            rank = max(rank, SEVERITY_RANK["warning"])

    if rank >= SEVERITY_RANK["error"] and confidence != "LOW":
        return "BLOCK"
    if rank >= SEVERITY_RANK["warning"]:
        return "WARN"
    return "ASYNC"


def overlaps(a, b, slack=3):
    """Two findings are considered the same underlying issue if they're in
    the same file within `slack` lines of each other. This is intentionally
    loose: different tools report slightly different line numbers for the
    same logical statement (e.g. the call vs. the assignment)."""
    if a["file"] != b["file"]:
        return False
    a_start = a["start_line"] or 0
    a_end = a["end_line"] or a_start
    b_start = b["start_line"] or 0
    b_end = b["end_line"] or b_start
    return not (a_end + slack < b_start or b_end + slack < a_start)


def dedupe_and_correlate(findings):
    """Group findings that refer to the same underlying location. A group
    with more than one distinct tool is a cross-tool agreement."""
    groups = []
    used = [False] * len(findings)
    for i, f in enumerate(findings):
        if used[i]:
            continue
        group = [f]
        used[i] = True
        for j in range(i + 1, len(findings)):
            if used[j]:
                continue
            if overlaps(f, findings[j]):
                group.append(findings[j])
                used[j] = True
        groups.append(group)
    return groups


def build_rows(groups, thresholds):
    rows = []
    counts = {"BLOCK": 0, "WARN": 0, "ASYNC": 0}
    for group in groups:
        # Use the highest-severity finding in the group to drive the verdict.
        primary = max(group, key=lambda f: SEVERITY_RANK.get(f["level"], 1))
        verdict = classify(primary, thresholds)
        counts[verdict] += 1

        tools = sorted({f["tool"] for f in group})
        rows.append(
            {
                "verdict": verdict,
                "file": primary["file"],
                "line": primary["start_line"],
                "tools": tools,
                "confirmed_by_multiple": len(tools) > 1,
                "rule_id": primary["rule_id"],
                "message": primary["message"],
                "security_severity": primary["security_severity"],
                "confidence": primary["confidence"],
            }
        )

    rows.sort(
        key=lambda r: (
            -SEVERITY_RANK.get(VERDICT_TO_LEVEL[r["verdict"]], 1),
            r["file"],
            r["line"] or 0,
        )
    )
    return rows, counts


def write_json(path, rows, counts, raw_count, sarif_files):
    Path(path).write_text(
        json.dumps(
            {
                "summary": counts,
                "raw_finding_count": raw_count,
                "sarif_files_scanned": sarif_files,
                "findings": rows,
            },
            indent=2,
        )
    )

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sarif-glob", action="append", required=True,
                         help="Glob pattern for SARIF files; repeatable.")
    parser.add_argument("--mode", choices=["report-only", "enforce"], default="report-only")
    parser.add_argument("--block-min-score", type=float, default=7.0,
                         help="security-severity score at/above which a finding is BLOCK.")
    parser.add_argument("--warn-min-score", type=float, default=4.0,
                         help="security-severity score at/above which a finding is at least WARN.")
    parser.add_argument("--output-md", default="triage-report.md")
    parser.add_argument("--output-json", default="triage-report.json")
    args = parser.parse_args()

    thresholds = {"block_min_score": args.block_min_score, "warn_min_score": args.warn_min_score}

    sarif_files = []
    for pattern in args.sarif_glob:
        sarif_files.extend(sorted(glob.glob(pattern, recursive=True)))

    if not sarif_files:
        print("::error::No SARIF files found — treating scan as failed, not clean.", file=sys.stderr)
        if args.mode == "enforce":
            write_json(args.output_json, [], {"BLOCK": 0, "WARN": 0, "ASYNC": 0}, 0, [])
            sys.exit(2)

    all_findings = []
    for path in sarif_files:
        all_findings.extend(load_sarif_findings(path))

    groups = dedupe_and_correlate(all_findings)
    rows, counts = build_rows(groups, thresholds)

    write_json(args.output_json, rows, counts, len(all_findings), sarif_files)

    print(
        f"Findings: {len(rows)} unique locations from {len(all_findings)} raw "
        f"results across {len(sarif_files)} SARIF file(s)"
    )
    print(f"BLOCK={counts['BLOCK']} WARN={counts['WARN']} ASYNC={counts['ASYNC']}")

    if args.mode == "enforce" and counts["BLOCK"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
