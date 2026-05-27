# Contributing to Nexuscone

Thank you for considering a contribution. Nexuscone is small and stays small on purpose. The most useful contributions are usually one of: a clear bug report, a focused pull request against an existing open issue, a documentation fix, or a question on a design decision that we should write up.

## Before you start

1. **Read the README.** Understand the trust model and the three integrity levels before proposing changes. The library is the extracted core of a larger governance product family and stays deliberately minimal.
2. **Check the open issues.** If your idea overlaps an existing one, comment on that thread rather than opening a duplicate.
3. **For larger changes, open an issue first.** A new backend, a new anchor adapter, a new CLI subcommand, or anything that touches the chain hash format needs a design discussion before code. We are happy to scope the work with you so the PR lands cleanly.

## How to file a good bug report

Use the bug report issue template. The information the template asks for is the information we need to reproduce; please fill it in even if the answer is "default".

The two highest-signal items are:

- A minimal reproducer. Even three lines that fail is better than a verbal description.
- The full traceback if Python raised. The traceback is more informative than a summary.

## How to file a good feature request

Use the feature request issue template. The two highest-signal items there are:

- What you are trying to do at the use-case level, not the API level. We can often satisfy the use case with an existing primitive plus a docs example.
- Whether you would accept building it yourself with guidance, or whether you are asking us to build it. Both are fine; we just need to know.

## Pull requests

Keep PRs focused. One feature or one fix per PR. If you find yourself touching unrelated code, that is a separate PR.

Local development setup:

```bash
git clone https://github.com/nexuscone/nexuscone.git
cd nexuscone
pip install -e ".[dev]"
pytest tests/ -v
```

Before pushing, please run the same checks CI runs:

```bash
ruff check src tests
mypy src
pytest tests/ -v
```

A PR is ready for review when:

1. CI is green on every supported Python (3.10, 3.11, 3.12, 3.13).
2. New code has tests. We currently sit around 99 test functions and keep that proportion as the codebase grows.
3. Public API changes update the README and the relevant docstring.
4. The PR description names the issue it closes, summarises the change in plain English, and notes any operator-visible impact (changes to CLI flags, file formats, environment variables).

We use small, clean commits. Squash if your branch history is messy; we will squash on merge if not.

## Coding style

Code follows the rules `ruff` and `mypy` enforce. We do not add stylistic comments beyond those tools' expectations. Comments are reserved for non-obvious decisions that a future reader would otherwise have to reverse-engineer.

British English in user-facing strings (README, CLI output, docstrings that get rendered). American English is fine inside variable names that follow third-party convention (for example, `color` if it appears in a library we depend on).

## Cryptographic changes

Any PR that touches the hash chain construction, the signature path, the anchor verification logic, or the canonical JSON serialisation requires extra care. Please:

- Open an issue first to discuss the change.
- Provide test cases that cover the new behaviour and that demonstrate v0.1.0 chains still verify under the format dispatch.
- Include a paragraph in the PR description explaining why the change is sound and what the new threat model coverage is.

We do not roll our own crypto. If you propose adding a new primitive, point us at the standard or the audited library that provides it.

## Code of Conduct

This project follows the Contributor Covenant v2.1. Read it in `CODE_OF_CONDUCT.md`. Contact the maintainer at `osi@aperintel.com` for any concerns.

## Licence

By submitting a contribution, you agree that your work will be licensed under the project's Apache 2.0 licence. The `CONTRIBUTORS.md` file lists everyone whose work has shipped in a release.

## Questions

If something is not covered here, open a GitHub Discussion or a low-priority issue tagged `question`. We would rather answer a question than have you guess.
