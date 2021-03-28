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
            return sprintf(result_str, "hypercall");
        case 0x003:
        case 0x103:
            return sprintf(result_str, "trap");
        case 0x004:
        case 0x104:
            return sprintf(result_str, "page_fault");
        case 0x005:
        case 0x105:
            return sprintf(result_str, "forced_invalid_op");
        case 0x006:
        case 0x106:
            return sprintf(result_str, "emulate_privop");
        case 0x007:
        case 0x107:
            return sprintf(result_str, "emulate_4G");
        case 0x008:
        case 0x108:
            return sprintf(result_str, "math_state_restore");
        case 0x009:
        case 0x109:
            return sprintf(result_str, "paging_fixup");
        case 0x00a:
        case 0x10a:
            return sprintf(result_str, "gdt_ldt_mapping_fault");
        case 0x00b:
        case 0x10b:
            return sprintf(result_str, "ptwr_emulation");
        case 0x00c:
        case 0x10c:
            return sprintf(result_str, "ptwr_emulation_pae");
        default:
            return 0;
    }
}

int get_pvcls_evinfo(const uint32_t event_id, const uint32_t *event_extra, char ***event_info)
{
    return 0;
}
