/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

// TODO:
// - this is quite tangled
// - many systems already provide a definition for this somewhere

#ifndef _N3N_ENDIAN_H_
#define _N3N_ENDIAN_H_

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <machine/endian.h>
#endif

#ifdef __OpenBSD__
#include <endian.h>
#define __BYTE_ORDER BYTE_ORDER
#if BYTE_ORDER == LITTLE_ENDIAN
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#endif /* __LITTLE_ENDIAN__ */
#else
#define __BIG_ENDIAN__
#endif/* BYTE_ORDER */
#endif/* __OPENBSD__ */


#if __BYTE_ORDER == __LITTLE_ENDIAN
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#endif
#else
#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__
#endif
#endif

#ifdef _WIN32
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__ 1
#endif
#endif

#if !(defined(__LITTLE_ENDIAN__) || defined(__BIG_ENDIAN__))
#if defined(__mips__)
#undef __LITTLE_ENDIAN__
#undef __LITTLE_ENDIAN
#define __BIG_ENDIAN__
#endif

/* Everything else */
#if (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#else
#define __BIG_ENDIAN__
#endif
#endif

#endif

#endif
