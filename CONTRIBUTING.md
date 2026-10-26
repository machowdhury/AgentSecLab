# Contributing

1. Branch from `develop`; do not push to `main`.
2. Run the tests ([Getting started](docs/GETTING_STARTED.md#run-the-tests)). If you change `academy-ui/`, rebuild with `sh scripts/build_academy_ui.sh` and commit the built assets.
3. If you change evidence data, run the relevant `scripts/export_*.py --check`.
4. Never commit `.env`, secrets, or local tool folders (`.cursor/`, `.claude/`, `.tmp-*/`).
5. Do not add scores, compliance claims, owners or approvals that the evidence does not state.

More: [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md). Use GitHub issues for questions and bugs.
