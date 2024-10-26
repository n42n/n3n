/**
 * Copyright (C) Hamish Coleman
 *
 * non public structure and function definitions
 */

#ifndef _MAINLOOP_H_
#define _MAINLOOP_H_

#include <n2n_typedefs.h>   // for n3n_runtime_data

int mainloop_runonce (fd_set *, fd_set *, struct n3n_runtime_data *);

#endif
