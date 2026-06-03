from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ChangedFile:
    path: str
    status: str
    additions: int
    deletions: int


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class CloseoutEvidence:
    provided: bool
    mentions_changed_file: bool
    mentions_verification: bool
    mentions_risks: bool
    mentions_rollback: bool


@dataclass(frozen=True)
class ProofPacketEvidence:
    path: str
    exists: bool
    schema_version: str
    verdict: str
    title: str
    changed_files: list[str]
    checks: list[CheckResult]
    findings: list[str]


@dataclass(frozen=True)
class ReadinessPacket:
    schema_version: str
    title: str
    verdict: str
    risk_level: str
    risk_score: int
    changed_files: list[ChangedFile]
    risk_tags: list[str]
    checks: list[CheckResult]
    closeout: CloseoutEvidence
    proof_packets: list[ProofPacketEvidence]
    missing_evidence: list[str]
    blocking_findings: list[str]
    reviewer_questions: list[str]


def read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def clean_path(path: str) -> str:
    path = path.strip()
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def status_from_paths(old_path: str, new_path: str) -> tuple[str, str]:
    if old_path == "/dev/null":
        return "added", clean_path(new_path)
    if new_path == "/dev/null":
        return "deleted", clean_path(old_path)
    return "modified", clean_path(new_path)


def parse_changed_files(diff_text: str) -> list[ChangedFile]:
    files: list[ChangedFile] = []
    current_path: str | None = None
    current_status = "modified"
    old_path = ""
    additions = 0
    deletions = 0

    def flush() -> None:
        nonlocal current_path, current_status, additions, deletions
        if current_path:
            files.append(ChangedFile(current_path, current_status, additions, deletions))
        current_path = None
        current_status = "modified"
        additions = 0
        deletions = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            flush()
            match = re.match(r"diff --git\s+(.+?)\s+(.+)$", line)
            if match:
                old_path = match.group(1)
                current_path = clean_path(match.group(2))
            continue
        if line.startswith("--- "):
            old_path = line[4:].strip()
            continue
        if line.startswith("+++ "):
            current_status, current_path = status_from_paths(old_path, line[4:].strip())
            continue
        if line.startswith("+") and not line.startswith("+++"):
            additions += 1
            continue
        if line.startswith("-") and not line.startswith("---"):
            deletions += 1
    flush()
    return files


def infer_tags(files: list[ChangedFile]) -> list[str]:
    tags: set[str] = set()
    for changed in files:
        path = changed.path.lower()
        suffix = Path(path).suffix
        parts = set(Path(path).parts)
        if suffix == ".py":
            tags.add("python")
        if suffix in {".js", ".jsx", ".ts", ".tsx"}:
            tags.add("javascript")
        if suffix in {".sh", ".bash", ".zsh"}:
            tags.add("shell")
        if suffix in {".yml", ".yaml"} or ".github" in parts or "workflows" in parts:
            tags.add("ci")
        if suffix == ".sql" or "migration" in path or "migrations" in parts:
            tags.add("database")
        if suffix in {".md", ".mdx", ".rst"} or "runbook" in path or "agents.md" in path:
            tags.add("documentation")
        if "test" in path or "tests" in parts:
            tags.add("tests")
        if any(word in path for word in ["auth", "secret", "token", "permission", "security"]):
            tags.add("security")
        if any(word in path for word in ["deploy", "release", "prod", "production"]):
            tags.add("release")
        if suffix in {".json", ".toml", ".ini", ".cfg", ".env"} or "config" in path:
            tags.add("configuration")
    return sorted(tags)


def risk_score(tags: list[str], files: list[ChangedFile]) -> int:
    value = min(len(files) * 5, 25)
    weights = {
        "security": 25,
        "database": 22,
        "release": 20,
        "ci": 16,
        "configuration": 12,
        "shell": 10,
        "python": 8,
        "javascript": 8,
        "documentation": 4,
        "tests": 2,
    }
    for tag in tags:
        value += weights.get(tag, 5)
    return min(value, 100)


def risk_level(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def parse_check(spec: str) -> CheckResult:
    name, separator, rest = spec.partition(":")
    if not separator:
        return CheckResult(spec.strip(), "not-run", "")
    raw_status, _, detail = rest.strip().partition(":")
    normalized = raw_status.lower().strip()
    aliases = {
        "ok": "pass",
        "passed": "pass",
        "pass": "pass",
        "success": "pass",
        "failed": "fail",
        "fail": "fail",
        "error": "fail",
        "skipped": "skipped",
        "skip": "skipped",
        "not-run": "not-run",
        "missing": "not-run",
    }
    status = aliases.get(normalized, "not-run")
    return CheckResult(name.strip(), status, detail.strip())


def check_passed(checks: list[CheckResult], *keywords: str) -> bool:
    for check in checks:
        haystack = f"{check.name} {check.detail}".lower()
        if check.status == "pass" and any(keyword in haystack for keyword in keywords):
            return True
    return False


def has_any_passing_check(checks: list[CheckResult]) -> bool:
    return any(check.status == "pass" for check in checks)


def inspect_closeout(closeout_text: str | None, files: list[ChangedFile]) -> CloseoutEvidence:
    if not closeout_text:
        return CloseoutEvidence(False, False, False, False, False)
    normalized = closeout_text.lower()
    file_paths = [changed.path.lower() for changed in files]
    file_names = [Path(changed.path).name.lower() for changed in files]
    return CloseoutEvidence(
        provided=True,
        mentions_changed_file=any(path in normalized for path in file_paths)
        or any(name in normalized for name in file_names),
        mentions_verification=any(
            token in normalized
            for token in ["verification", "verified", "test", "tests", "command", "checked"]
        ),
        mentions_risks=any(
            token in normalized
            for token in ["risk", "risks", "limitation", "not verified", "not run", "pending", "blocker"]
        ),
        mentions_rollback="rollback" in normalized,
    )


def parse_proof_packet(
    spec: str,
    current_files: list[ChangedFile],
    cwd: Path | None = None,
) -> ProofPacketEvidence:
    packet_path = Path(spec).expanduser()
    if not packet_path.is_absolute() and cwd is not None:
        packet_path = cwd / packet_path

    display_path = spec
    if not packet_path.exists() or not packet_path.is_file():
        return ProofPacketEvidence(display_path, False, "", "", "", [], [], ["proof packet file is missing"])

    try:
        data = json.loads(packet_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return ProofPacketEvidence(display_path, True, "", "", "", [], [], [f"proof packet JSON is invalid: {exc}"])

    if not isinstance(data, dict):
        return ProofPacketEvidence(display_path, True, "", "", "", [], [], ["proof packet JSON must be an object"])

    findings: list[str] = []
    schema_version = str(data.get("schema_version") or "")
    verdict_value = str(data.get("verdict") or "")
    title = str(data.get("title") or "")
    if schema_version != "agent-proof-packet.v1":
        findings.append("proof packet schema_version is not agent-proof-packet.v1")
    if verdict_value != "complete":
        findings.append(f"proof packet verdict is {verdict_value or 'missing'}; expected complete")

    raw_changed_files = data.get("changed_files")
    packet_files: list[str] = []
    if not isinstance(raw_changed_files, list):
        findings.append("proof packet changed_files must be a list")
    else:
        for item in raw_changed_files:
            if isinstance(item, dict) and item.get("path"):
                packet_files.append(str(item["path"]))
            else:
                findings.append("proof packet changed_files item is missing a path")

    current_paths = sorted(changed.path for changed in current_files)
    packet_paths = sorted(packet_files)
    if packet_paths != current_paths:
        findings.append("proof packet changed files do not match the current diff")

    raw_checks = data.get("checks")
    packet_checks: list[CheckResult] = []
    if not isinstance(raw_checks, list):
        findings.append("proof packet checks must be a list")
    else:
        for item in raw_checks:
            if isinstance(item, dict) and item.get("name"):
                packet_checks.append(
                    CheckResult(
                        str(item["name"]),
                        str(item.get("status") or "not-run"),
                        str(item.get("detail") or ""),
                    )
                )
            else:
                findings.append("proof packet check item is missing a name")

    return ProofPacketEvidence(
        display_path,
        True,
        schema_version,
        verdict_value,
        title,
        packet_files,
        packet_checks,
        findings,
    )


def missing_evidence_for(
    tags: list[str],
    level: str,
    checks: list[CheckResult],
    closeout: CloseoutEvidence,
    proof_packets: list[ProofPacketEvidence],
) -> list[str]:
    missing: list[str] = []
    if not has_any_passing_check(checks):
        missing.append("At least one passing verification check is required.")
    if not check_passed(checks, "scope"):
        missing.append("Scope evidence is missing; run or record `agent-scope-guard`.")
    if {"python", "javascript", "tests"} & set(tags) and not check_passed(
        checks, "test", "unittest", "pytest", "ci"
    ):
        missing.append("Code changes need a passing test or CI check.")
    if {"security", "configuration"} & set(tags) and not check_passed(checks, "secret", "sentinel"):
        missing.append("Security or config changes need secret-scan evidence.")
    if {"ci", "documentation"} & set(tags) and not check_passed(checks, "runbook", "workflow", "ci"):
        missing.append("CI or documentation changes need runbook/workflow evidence.")
    if {"database", "release"} & set(tags) or level == "high":
        if not check_passed(checks, "rollback") and not closeout.mentions_rollback:
            missing.append("Database, release, or high-risk changes need rollback evidence.")
    if level in {"medium", "high"} and not closeout.provided:
        missing.append("Medium and high-risk changes need a closeout note.")
    if closeout.provided and not closeout.mentions_changed_file:
        missing.append("Closeout must name at least one changed file.")
    if closeout.provided and not closeout.mentions_verification:
        missing.append("Closeout must state exact verification evidence.")
    if closeout.provided and not closeout.mentions_risks:
        missing.append("Closeout must state risks, limitations, or checks not run.")
    if any(packet.findings for packet in proof_packets):
        missing.append("All proof packets must be complete and match the current diff.")
    return missing


def blocking_findings_for(
    checks: list[CheckResult],
    proof_packets: list[ProofPacketEvidence],
) -> list[str]:
    findings = [f"Check failed: {check.name}" for check in checks if check.status == "fail"]
    for packet in proof_packets:
        findings.extend(f"Proof packet `{packet.path}`: {finding}" for finding in packet.findings)
    return findings


def reviewer_questions(tags: list[str], missing: list[str], blockers: list[str]) -> list[str]:
    questions = ["Does the diff stay inside the declared task scope?"]
    if missing:
        questions.append("Which missing evidence must be produced before merge?")
    if blockers:
        questions.append("Should the agent rerun with the failed check output as context?")
    if "security" in tags:
        questions.append("Did any permission, token, or auth behavior change?")
    if "database" in tags:
        questions.append("Is the rollback path tested for schema and data impact?")
    if "release" in tags:
        questions.append("Who is authorized to approve production rollback?")
    if "ci" in tags:
        questions.append("Could workflow permissions or triggers change required checks?")
    return questions


def verdict(blockers: list[str], missing: list[str]) -> str:
    if blockers:
        return "blocked"
    if missing:
        return "needs-review"
    return "ready"


def build_packet(
    diff_text: str,
    title: str,
    check_specs: list[str] | None = None,
    closeout_text: str | None = None,
    proof_packet_specs: list[str] | None = None,
    cwd: Path | None = None,
) -> ReadinessPacket:
    files = parse_changed_files(diff_text)
    tags = infer_tags(files)
    score = risk_score(tags, files)
    level = risk_level(score)
    checks = [parse_check(spec) for spec in check_specs or []]
    proof_packets = [parse_proof_packet(spec, files, cwd) for spec in proof_packet_specs or []]
    for packet in proof_packets:
        checks.extend(packet.checks)
    checks.extend(
        CheckResult(
            f"proof packet: {packet.title or packet.path}",
            "pass" if not packet.findings else "fail",
            packet.verdict or "missing verdict",
        )
        for packet in proof_packets
    )
    closeout = inspect_closeout(closeout_text, files)
    blockers = blocking_findings_for(checks, proof_packets)
    missing = missing_evidence_for(tags, level, checks, closeout, proof_packets)
    return ReadinessPacket(
        schema_version="agent-merge-readiness.v1",
        title=title,
        verdict=verdict(blockers, missing),
        risk_level=level,
        risk_score=score,
        changed_files=files,
        risk_tags=tags,
        checks=checks,
        closeout=closeout,
        proof_packets=proof_packets,
        missing_evidence=missing,
        blocking_findings=blockers,
        reviewer_questions=reviewer_questions(tags, missing, blockers),
    )


def render_markdown(packet: ReadinessPacket) -> str:
    lines = [
        f"# Merge Readiness: {packet.title}",
        "",
        f"Verdict: {packet.verdict}",
        f"Risk level: {packet.risk_level}",
        f"Risk score: {packet.risk_score}/100",
        "",
        "## Risk Tags",
        "",
    ]
    lines.extend(f"- {tag}" for tag in packet.risk_tags or ["none"])
    lines.extend(["", "## Changed Files", ""])
    lines.extend(f"- `{file.path}` ({file.status}, +{file.additions}/-{file.deletions})" for file in packet.changed_files)
    lines.extend(["", "## Passing Checks", ""])
    passing = [check.name for check in packet.checks if check.status == "pass"]
    lines.extend(f"- {name}" for name in passing or ["none"])
    lines.extend(["", "## Blocking Findings", ""])
    lines.extend(f"- {finding}" for finding in packet.blocking_findings or ["none"])
    lines.extend(["", "## Proof Packets", ""])
    for proof_packet in packet.proof_packets:
        status = "complete" if not proof_packet.findings else "invalid"
        lines.append(
            f"- {status}: `{proof_packet.path}` verdict `{proof_packet.verdict or 'missing'}` "
            f"({len(proof_packet.changed_files)} changed file(s))"
        )
        for finding in proof_packet.findings:
            lines.append(f"  - finding: {finding}")
    if not packet.proof_packets:
        lines.append("- none")
    lines.extend(["", "## Missing Evidence", ""])
    lines.extend(f"- {item}" for item in packet.missing_evidence or ["none"])
    lines.extend(["", "## Reviewer Questions", ""])
    lines.extend(f"- {question}" for question in packet.reviewer_questions)
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-merge-readiness")
    parser.add_argument("diff", help="Path to unified diff, or '-' to read from stdin.")
    parser.add_argument("--title", required=True, help="Human-readable change title.")
    parser.add_argument(
        "--check",
        action="append",
        default=[],
        help="Evidence in the form 'name:pass', 'name:fail', 'name:skipped', or 'name:not-run'.",
    )
    parser.add_argument("--closeout", help="Optional path to agent closeout Markdown.")
    parser.add_argument(
        "--proof-packet",
        action="append",
        default=[],
        help="agent-proof-packet.v1 JSON file that must be complete and match the diff.",
    )
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    diff_text = read_text(args.diff)
    if not diff_text.strip():
        print("No diff content provided.", file=sys.stderr)
        return 2
    closeout_text = read_text(args.closeout) if args.closeout else None
    packet = build_packet(diff_text, args.title, args.check, closeout_text, args.proof_packet, Path.cwd())
    if args.format == "json":
        print(json.dumps(asdict(packet), indent=2))
    else:
        print(render_markdown(packet), end="")
    return 0 if packet.verdict == "ready" else 1
