SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Older testing framework

An older test framework is still included.  This has a different coverage and
expected use case than the preferred builtin test framework.

This older framework is built around diffing the expected user visible outputs
from running various commands.  It was not intended to be used for checking
the internals of the various library functions.

Some internals have been exposed by writing and compiling small programs that
then output their test information.  This is a deprecated process and no new
tests will be added that work like this without a clearly and concisely
described reason.

Where this framework is still expected to be useful is when making management
API calls - as this also provides a way to show how to make an API call and
the expected reply.  This helps to enforce the requirement to not accidentally
introduce API changes.

It is expected that many of the old tests in the legacy framework will be
migrated to the builtin test framework, eventually allowing the legacy
framework to be simplified and focused more clearly on this user-visible API
validation job.

The legacy testing framework is run as part of the `make test` command.
