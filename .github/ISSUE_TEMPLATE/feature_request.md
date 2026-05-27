---
name: Feature request
about: Propose a new capability, backend, or adapter
title: "[Feature] "
labels: enhancement
assignees: ''
---

## Use case

What are you trying to accomplish at the application level? Describe the user problem first, not the API shape you have in mind. A good test is whether someone reading just this paragraph would understand why this matters.

## Proposed shape

How you would expect to interact with the feature. Concrete is better than abstract. If you have an API sketch:

```python
# show the call site you wish you could write
```

If the request is for a new CLI subcommand or flag, sketch the command line and the output.

## Alternatives considered

If you have already tried something with the current API, describe what you tried and why it did not fit. This helps avoid suggesting things you have already ruled out.

## Scope question

- Could this be solved with an existing primitive plus a docs example, instead of new library code?
- Is this a thin layer on top of Nexuscone, or does it require a change to the chain format, the verifier, or the signing path?
- Would you be willing to implement it with maintainer guidance, or are you asking us to build it? Both are fine; we just need to know.

## Related issues or PRs

Link any prior discussion that touches the same ground.
