/*
 * SPDX-FileCopyrightText: Copyright Hamish Coleman
 * SPDX-License-Identifier: LGPL-2.1-only
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
