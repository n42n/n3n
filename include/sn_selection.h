/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#ifndef _SN_SELECTION_
#define _SN_SELECTION_

// FIXME: including the private header in a public interface, should untangle
#include "../src/peer_info.h" // for peer_info, peer_info_t

typedef char selection_criterion_str_t[SN_SELECTION_CRITERION_BUF_SIZE];

#include "n2n.h"

/* selection criterion's functions */
int sn_selection_criterion_init (peer_info_t *peer);
int sn_selection_criterion_default (SN_SELECTION_CRITERION_DATA_TYPE *selection_criterion);
int sn_selection_criterion_bad (SN_SELECTION_CRITERION_DATA_TYPE *selection_criterion);
int sn_selection_criterion_good (SN_SELECTION_CRITERION_DATA_TYPE *selection_criterion);
int sn_selection_criterion_calculate (struct n3n_runtime_data *eee, peer_info_t *peer, SN_SELECTION_CRITERION_DATA_TYPE *data);

/* common data's functions */
int sn_selection_criterion_common_data_default (struct n3n_runtime_data *eee);

/* sorting function */
int sn_selection_sort (peer_info_t **peer_list);

/* gathering data function */
SN_SELECTION_CRITERION_DATA_TYPE sn_selection_criterion_gather_data (struct n3n_runtime_data *sss);

/* management port output function */
extern char * sn_selection_criterion_str (struct n3n_runtime_data *eee, selection_criterion_str_t out, peer_info_t *peer);


#endif /* _SN_SELECTION_ */
