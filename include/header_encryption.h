/**
 * (C) 2007-22 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#include "n2n_typedefs.h"
#include "speck.h"          // for struct speck_context_t

int packet_header_decrypt (uint8_t packet[], uint16_t packet_len,
                           char *community_name,
                           struct speck_context_t *ctx,
                           struct speck_context_t *ctx_iv,
                           uint64_t *stamp);

int packet_header_encrypt (uint8_t packet[], uint16_t header_len, uint16_t packet_len,
                           struct speck_context_t *ctx,
                           struct speck_context_t *ctx_iv,
                           uint64_t stamp);

void packet_header_setup_key (const char *community_name,
                              struct speck_context_t **ctx_static,
                              struct speck_context_t **ctx_dynamic,
                              struct speck_context_t **ctx_iv_static,
                              struct speck_context_t **ctx_iv_dynamic);

void packet_header_change_dynamic_key (uint8_t *key_dynamic,
                                       struct speck_context_t **ctx_dynamic,
                                       struct speck_context_t **ctx_iv_dynamic);
