/**
 * XenTrace data processing interface for KernelShark - Copyright (C) 2021
 * Giuseppe Eletto <peppe.eletto@gmail.com>
 * Dario Faggioli  <dfaggioli@suse.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 * USA
 */

#ifndef _GNU_SOURCE
/** Use GNU C Library. */
#define _GNU_SOURCE
#endif // _GNU_SOURCE

#include <stdio.h>

#include "events.h"

//
// EVENT NAME
//

int get_basecls_evname(const uint32_t event_id, char *result_str)
{
    int event_sub = event_id & 0x00000fff;
    switch (event_sub) {
        case 0x001:
            return EVNAME(result_str, "lost_records");
        case 0x002:
            return EVNAME(result_str, "wrap_buffer");
        case (TRC_GEN | 0x004):
            return EVNAME(result_str, "trace_irq");
        //case TRC_LOST_RECORDS_END:
        //    return asnprintf(result_str, STR_EVNAME_SIZE, "lost_records_end");
        default:
            return 0;
    }
}

//
// EVENT INFO
//

int get_basecls_evinfo(const uint32_t event_id,
                    const uint32_t *event_extra, char *result_str)
{
    int event_sub = event_id & 0x00000fff;
    switch (event_sub) {
        case 0x001:
        case 0x002:
            return EVINFO(result_str, "0x%08x", event_extra[0]);
        case (TRC_GEN | 0x004):
            return EVINFO(result_str, "vector = %d, count = %d, tot_cycles = 0x%08x, max_cycles = 0x%08x",
                                event_extra[0], event_extra[1], event_extra[2], event_extra[3]);
        //case TRC_LOST_RECORDS_END:
        //    return asnprintf(result_str, STR_EVINFO_SIZE, "??");
        default:
            return 0;
    }
}