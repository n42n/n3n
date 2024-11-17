/*
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

// TODO:
// - on linux there are headers with these predefined
// - on windows, there are different predefines
// - use them!
#ifndef MAX
#define MAX(a, b) (((a) < (b)) ? (b) : (a))
#endif

#ifndef MIN
#define MIN(a, b) (((a) >(b)) ? (b) : (a))
#endif
