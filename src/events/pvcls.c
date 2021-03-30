/**
 * XenTrace data processing interface for KernelShark - Copyright (C) 2021
 * Giuseppe Eletto <peppe.eletto@gmail.com>
 * Dario Faggioli  <dfaggioli@suse.com>
 *
 * This library is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU LGPLv3 along with
 * this library. If not, see <https://www.gnu.org/licenses/>.
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

int get_pvcls_evname(const uint32_t event_id, char *result_str)
{
    int event_sub = event_id & 0x00000fff;
    switch (event_sub) {
        case 0x001:
        case 0x101:
        case 0x00d:
        case 0x00e: // TRC_PV_SUBCALL
            return EVNAME(result_str, "hypercall");
        case 0x003:
        case 0x103:
            return EVNAME(result_str, "trap");
        case 0x004:
        case 0x104:
            return EVNAME(result_str, "page_fault");
        case 0x005:
        case 0x105:
            return EVNAME(result_str, "forced_invalid_op");
        case 0x006:
        case 0x106:
            return EVNAME(result_str, "emulate_privop");
        case 0x007:
        case 0x107:
            return EVNAME(result_str, "emulate_4G");
        case 0x008:
        case 0x108:
            return EVNAME(result_str, "math_state_restore");
        case 0x009:
        case 0x109:
            return EVNAME(result_str, "paging_fixup");
        case 0x00a:
        case 0x10a:
            return EVNAME(result_str, "gdt_ldt_mapping_fault");
        case 0x00b:
        case 0x10b:
            return EVNAME(result_str, "ptwr_emulation");
        case 0x00c:
        case 0x10c:
            return EVNAME(result_str, "ptwr_emulation_pae");
        default:
            return 0;
    }
}

//
// EVENT INFO
//

int get_pvcls_evinfo(const uint32_t event_id,
                const uint32_t *event_extra, char *result_str)
{
    int event_sub = event_id & 0x00000fff;
    switch (event_sub) {
        case 0x001:
            return EVINFO(result_str, "eip = 0x%08x, eax = 0x%08x", event_extra[0],
                                event_extra[1]);
        case 0x101:
            return EVINFO(result_str, "rip = 0x%08x%08x, eax = 0x%08x", event_extra[1],
                                event_extra[0], event_extra[2]);
        case 0x003:
            return EVINFO(result_str, "eip = 0x%08x, trapnr:error = 0x%08x", event_extra[0],
                                event_extra[1]);
        case 0x103:
            return EVINFO(result_str, "rip = 0x%08x%08x, trapnr:error = 0x%08x", event_extra[1],
                                event_extra[0], event_extra[2]);
        case 0x004:
            return EVINFO(result_str, "eip = 0x%08x, addr = 0x%08x, error = 0x%08x", event_extra[0],
                                event_extra[1], event_extra[2]);
        case 0x104:
            return EVINFO(result_str, "rip = 0x%08x%08x, addr = 0x%08x%08x, error = 0x%08x",
                                event_extra[1], event_extra[0], event_extra[3], event_extra[2], event_extra[4]);
        case 0x005:
        case 0x006:
        case 0x007:
            return EVINFO(result_str, "eip = 0x%08x", event_extra[0]);
        case 0x105:
        case 0x106:
        case 0x107:
            return EVINFO(result_str, "rip = 0x%08x%08x", event_extra[1], event_extra[0]);
        //case 0x008:
        //    return EVINFO(result_str, "");
        //case 0x108:
        //    return EVINFO(result_str, "");
        case 0x009:
            return EVINFO(result_str, "eip = 0x%08x, addr = 0x%08x", event_extra[0], 
                                event_extra[1]);
        case 0x109:
            return EVINFO(result_str, "rip = 0x%08x%08x, addr = 0x%08x%08x", event_extra[1], 
                                event_extra[0], event_extra[3], event_extra[2]);
        case 0x00a:
            return EVINFO(result_str, "eip = 0x%08x, offset = 0x%08x", event_extra[0], 
                                event_extra[1]);
        case 0x10a:
            return EVINFO(result_str, "rip = 0x%08x%08x, offset = 0x%08x%08x", event_extra[1], 
                                event_extra[0], event_extra[3], event_extra[2]);
        case 0x00b:
        case 0x00c:
            return EVINFO(result_str, "addr = 0x%08x, eip = 0x%08x, npte = 0x%08x%08x", event_extra[2], 
                                event_extra[3], event_extra[1], event_extra[0]);
        case 0x10b:
        case 0x10c:
            return EVINFO(result_str, "addr = 0x%08x%08x, rip = 0x%08x%08x, npte = 0x%08x%08x", 
                                event_extra[3], event_extra[2], event_extra[5], event_extra[4], event_extra[1], 
                                event_extra[0]);
        case 0x00d:
        case 0x00e: // TRC_PV_SUBCALL
            return EVINFO(result_str, "op = 0x%08x", event_extra[0]);
        default:
            return 0;
    }
}
