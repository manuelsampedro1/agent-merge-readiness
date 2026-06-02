import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from agent_merge_readiness.cli import build_packet, main, parse_changed_files


RISKY_DIFF = """diff --git a/.github/workflows/deploy.yml b/.github/workflows/deploy.yml
index 1111111..2222222 100644
--- a/.github/workflows/deploy.yml
+++ b/.github/workflows/deploy.yml
@@ -1,2 +1,3 @@
 name: Deploy
+permissions: write-all
diff --git a/migrations/20260602_add_users.sql b/migrations/20260602_add_users.sql
new file mode 100644
--- /dev/null
+++ b/migrations/20260602_add_users.sql
@@ -0,0 +1,2 @@
+ALTER TABLE users ADD COLUMN plan TEXT;
diff --git a/src/auth.py b/src/auth.py
index 3333333..4444444 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1 +1,2 @@
+TOKEN_NAME = "session"
"""


GOOD_CLOSEOUT = """# Closeout

Changed files: `.github/workflows/deploy.yml`, `migrations/20260602_add_users.sql`, `src/auth.py`.

Verification:
- `PYTHONPATH=src python -m unittest discover -s tests` passed.
- `agent-scope-guard` passed.
- Secret scan passed.
- Runbook drift check passed.
- Rollback plan reviewed.

Risks and limitations:
- Risk remains around deploy permissions; rollback is documented and must be approved before production use.
"""


class MergeReadinessTests(unittest.TestCase):
    def test_parse_changed_files(self) -> None:
        files = parse_changed_files(RISKY_DIFF)

        self.assertEqual(len(files), 3)
        self.assertEqual(files[1].status, "added")

    def test_needs_review_when_evidence_is_missing(self) -> None:
        packet = build_packet(RISKY_DIFF, "Deploy auth migration")

        self.assertEqual(packet.verdict, "needs-review")
        self.assertIn("security", packet.risk_tags)
        self.assertTrue(any("Scope evidence" in item for item in packet.missing_evidence))

    def test_blocked_when_check_fails(self) -> None:
        packet = build_packet(
            RISKY_DIFF,
            "Deploy auth migration",
            ["scope guard:pass", "unit tests:fail"],
            GOOD_CLOSEOUT,
        )

        self.assertEqual(packet.verdict, "blocked")
        self.assertTrue(any("unit tests" in finding for finding in packet.blocking_findings))

    def test_ready_when_required_evidence_exists(self) -> None:
        packet = build_packet(
            RISKY_DIFF,
            "Deploy auth migration",
            [
                "scope guard:pass",
                "unit tests:pass",
                "secret scan:pass",
                "runbook drift:pass",
                "rollback plan:pass",
            ],
            GOOD_CLOSEOUT,
        )

        self.assertEqual(packet.verdict, "ready")
        self.assertEqual(packet.missing_evidence, [])

    def test_cli_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            diff_path = Path(tmp) / "sample.diff"
            closeout_path = Path(tmp) / "closeout.md"
            diff_path.write_text(RISKY_DIFF, encoding="utf-8")
            closeout_path.write_text(GOOD_CLOSEOUT, encoding="utf-8")
            stream = StringIO()

            with redirect_stdout(stream):
                exit_code = main(
                    [
                        str(diff_path),
                        "--title",
                        "Deploy auth migration",
                        "--check",
                        "scope guard:pass",
                        "--check",
                        "unit tests:pass",
                        "--check",
                        "secret scan:pass",
                        "--check",
                        "runbook drift:pass",
                        "--check",
                        "rollback plan:pass",
                        "--closeout",
                        str(closeout_path),
                        "--format",
                        "json",
                    ]
                )

            payload = json.loads(stream.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["schema_version"], "agent-merge-readiness.v1")
        self.assertEqual(payload["verdict"], "ready")

    def test_cli_needs_review_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            diff_path = Path(tmp) / "sample.diff"
            diff_path.write_text(RISKY_DIFF, encoding="utf-8")
            stream = StringIO()

            with redirect_stdout(stream):
                exit_code = main([str(diff_path), "--title", "Deploy auth migration"])

        self.assertEqual(exit_code, 1)
        self.assertIn("Verdict: needs-review", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
