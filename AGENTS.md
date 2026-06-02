# AGENTS.md

## Goal

Keep `agent-merge-readiness` a small, local-first CLI that turns a coding-agent diff, check results, and closeout evidence into an auditable merge verdict.

## Constraints

- Prefer dependency-free Python in `src/agent_merge_readiness/`.
- Keep the CLI useful from a fresh clone with `python3`, `make`, and no hosted service.
- Do not commit secrets, `.env` files, generated package metadata, or fake examples.
- Treat `needs-review` and `blocked` as non-ready gate outcomes.

## Verification

Run these before publishing changes:

```sh
make test
make lint
make build
make smoke
git diff --check
```

Use `repo-flightcheck --check-remote --strict --threshold 80` after a public push.
