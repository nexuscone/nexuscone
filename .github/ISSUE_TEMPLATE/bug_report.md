---
name: Bug report
about: Report a defect in the library or CLI
title: "[Bug] "
labels: bug
assignees: ''
---

## What happened

A clear description of the unexpected behaviour.

## What you expected

A clear description of what you thought should happen.

## How to reproduce

Minimal code (ideally three to ten lines) that triggers the bug. Even better: a self-contained snippet someone can paste into a fresh venv.

```python
# paste the smallest reproducer here
```

If the issue is on the CLI, paste the command line and the output verbatim:

```
$ nexuscone-verify ...
```

## Environment

- nexuscone version: `pip show nexuscone | grep Version`
- Python version: `python --version`
- Operating system and version:
- Optional extras installed: `[signing]`, anchor backends, etc.

## Traceback

If Python raised, paste the full traceback inside a code block. Tracebacks are more informative than summaries.

```
paste the full traceback here
```

## Anything else

Context, screenshots, related issues, links to the application you are integrating into.
