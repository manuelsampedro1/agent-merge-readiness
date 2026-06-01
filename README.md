# Agent Merge Readiness

Decide whether a coding-agent change is ready to merge, needs reviewer work, or must be blocked.

Agents often finish with a confident closeout, but reviewers still need to answer harder questions:

- What changed?
- Which checks actually passed?
- Is there rollback evidence for risky files?
- Does the closeout name files, verification, and limitations?
- Is the merge ready or just plausible?

`agent-merge-readiness` reads a unified diff, optional check results, and an optional closeout note. It returns a compact readiness packet.

## Install

```sh
python -m pip install --upgrade pip
python -m pip install -e .
```

Or run without installing:

```sh
PYTHONPATH=src python -m agent_merge_readiness examples/risky.diff \
  --title "Deploy workflow migration" \
  --check "scope guard:pass" \
  --check "unit tests:pass" \
  --check "secret scan:pass" \
  --check "runbook drift:pass" \
  --check "rollback plan:pass" \
  --closeout examples/closeout.md
```

## Usage

```sh
git diff -- . | agent-merge-readiness - --title "Current agent change"
agent-merge-readiness examples/risky.diff --title "Risky change" --format json
agent-merge-readiness examples/risky.diff --title "Risky change" --check "ci:fail"
```

## Example Output

```md
# Merge Readiness: Deploy workflow migration

Verdict: ready
Risk level: high
Risk score: 100/100

## Passing Checks

- scope guard
- unit tests
- secret scan
- runbook drift
- rollback plan
```

## Evidence Model

The tool is intentionally strict:

- Any failed check blocks the merge.
- Every agent diff needs scope evidence.
- Code changes need a passing test or CI check.
- Security or config changes need secret-scan evidence.
- CI or docs changes need runbook/workflow evidence.
- Database, release, or high-risk changes need rollback evidence.
- Medium and high-risk changes need a closeout with files, verification, and risks.

It does not replace human review. It turns reviewer expectations into a repeatable gate.

## Development

```sh
PYTHONPATH=src python -m unittest discover -s tests
PYTHONPATH=src python -m agent_merge_readiness examples/risky.diff --title "Sample" --format json
```

## Fit With The Agent Workflow Stack

- `agent-task-contract`: define the task before the run.
- `agent-scope-guard`: prove the diff stayed in bounds.
- `agent-change-risk`: choose gates from changed paths.
- `agent-merge-readiness`: decide whether evidence is enough to merge.
- `agent-run-ledger`: keep the run auditable after the fact.
