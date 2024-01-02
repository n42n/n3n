/*
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Wrapper to call initfuncs
 */

// prototype all the needed initfuncs
void n3n_conffile_defs_init ();

void n3n_initfuncs () {
    // TODO:
    // - ideally, these functions would all be defined statically as
    //   constructors within their own object file, but we need to reference
    //   them externally or the linker will never link that object

    n3n_conffile_defs_init();
}
