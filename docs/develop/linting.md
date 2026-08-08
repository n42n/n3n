SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Linting

Checking all the lint rules can be done with `make lint`

- All python code is linted with `flake8`
- C code is linted using `uncrustify` with the specific config found in the
  `uncrustify.cfg` file
