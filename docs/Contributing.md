SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: Copyright 2022 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Contributing to the n3n project

This outlines some of the basic steps that this project uses for
contributions.

## Provide patches or pull requests

- Ensure you follow the code style (Use `make lint` to check,
  [more info](develop/linting.md))
- Ensure that the tests pass (Use `make test` to check, [more
  info](develop/testing.md))
- Ensure that the licence and copyright of any imported code is marked
- Ensure that each commit has a commit message that clearly explains "why" the
  commit was made (Note, you should not explain "what" as that should be clear
  in the commit diff)
- The language used for documentation, commit messages and code comments is
  English.
- Ensure that each commit has a single clear purpose, do not mix multiple
  things into one change (Eg, do not have both whitespace fixes and functional
  improvements in one commit, or do not have a new feature and a bugfix for an
  unrelated feature)
- Ensure that all the commits in your proposed set of changes have a common
  theme that joins them together.  If you have two different topics, they
  should probably go into two different Pull Requests as this makes it easier
  to discuss the change, easier to review the change and easier to update the
  PR after any review comments.
- If you have used any software to assist with creation of your patch, ensure
  you declare that usage in the commit message as it may help the reviewer to
  understand what questions to ask.
- As the submitter of the change, you need to understand what the change is
  and how it works - you must be prepared to answer questions about it and be
  able to adjust it to fit the project.  Essentially, since you are proposing
  it, you need to own it.

## Other ways to Contribute

- Update an [open issue](https://github.com/n42n/n3n/issues) or create a new
  one with detailed information
- Propose new features
- Improve the documentation
