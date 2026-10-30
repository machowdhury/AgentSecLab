# Contributing

1. Open pull requests against the default branch from your own branch.
2. Run the tests ([Getting started](docs/GETTING_STARTED.md#for-contributors)). If you change `academy-ui/`, rebuild with `sh scripts/build_academy_ui.sh` and commit the built assets.
3. If you change evidence data, run the relevant `scripts/export_*.py --check`.
4. Never commit `.env`, secrets, or local tool folders (an internal record (not published), `.claude/`, `.tmp-*/`).
5. Do not add scores, compliance claims, owners or approvals that the evidence does not state.

More: [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md). Use GitHub issues for questions and bugs.

## Reporting a security issue

AgentSecLab contains intentionally vulnerable lab profiles; those are by design. If you find a weakness in the gateway, the installer, the Attack Service's launch boundary or anything that could harm a participant's machine, please report it privately through GitHub's private vulnerability reporting for this repository rather than in a public issue (see [SECURITY.md](SECURITY.md)).
