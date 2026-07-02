SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: Copyright 2022 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Contributing to the n3n project

This outlines some of the basic steps that this project uses for
contributions.

## Provide patches or pull requests

- Ensure you follow the code style (Use `make lint` to check)
- Ensure that the tests pass (Use `make test` to check)
- Ensure that the licence and copyright of any imported code is marked
- Ensure that each commit has a commit message that clearly explains "why" the
  commit was made (Note, you should not explain "what" as that should be clear
  in the commit diff)
- Enaure that each commit has a single clear purpose, do not mix multiple
  things into one change (Eg, do not have both whitespace fixes and functional
  improvements in one commit, or do not have a new feature and a bugfix for an
  unrelated feature)
- Ensure that all the commits in your proposed set of changes have a common
  theme that joins them together.  If you have two different topics, they
  should probably go into two different Pull Requests as this makes it easier
  to discuss the change, easier to review the change and easier to update the
  PR after any review comments.

## Other ways to Contribute

- Update an [open issue](https://github.com/n42n/n3n/issues) or create a new
  one with detailed information
- Propose new features
- Improve the documentation
