This directory contains metadata related to running the legacy testing.
(See [devlop legacy testing](../docs/develop/testing_legacy.md) doc for
details about the framework)

The legacy testing framework is expected to eventually only contain
integration testing - all other types of tests are expected to be moved into
builtin tests.  Once this has all happened, it is expected that the tests
will be refactored to remove the "legacy" nature.

The metadata here is one of three types:

## Named test suite list of tests.

(eg `tests_builtin.list`)

Each `list` file describes one test suite and contains the list of the test
steps that will be run for that suite.  The `scripts/test_harness.sh` script
is given the `list` filename as a parameter to run as part of the Makefile.
All `list` files should be named with a prefix `tests_`, a midfix of the
test suite name and a suffix of `.list`

They contain a list of the test steps - scripts or binaries - that are run as
part of that test suite.  The named scripts are expected to be found in the
scripts/ subdirectory and the named binaries are expected to be found in the
tools/ subdirectory.

Do not put shell code, variables, functions or other logic in these files.
They should contain only comments, blank lines and the names of the tests to
run.

## Expected results files

(eg `test_builtin_edge.sh.expected`)

Named exactly after the test step, this is the expected text from the stdout
generated when running that test step.  This is used as a known good output
to diff against when running the test steps.

## Temporary actual results files

(eg `test_builtin_edge.sh.out`)

When a test step is run, the generated output is saved for later analysis
(usually in the case of investigating an output discrepancy).

These temporary files are stored in this directory, but are not committed to
the git repository.
