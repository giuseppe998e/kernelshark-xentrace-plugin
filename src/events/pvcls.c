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

#include "events.h"

int get_pvcls_evname(const uint32_t event_id, char ***event_name)
{
    int event_sub = event_id & 0x00000fff;
    switch (event_sub) {
        case 0x001:
        case 0x101:
        case 0x00d:
        case 0x00e:
            return asprintf(*event_name, "hypercall");
        case 0x003:
        case 0x103:
            return asprintf(*event_name, "trap");
        case 0x004:
        case 0x104:
            return asprintf(*event_name, "page_fault");
        case 0x005:
        case 0x105:
            return asprintf(*event_name, "forced_invalid_op");
        case 0x006:
        case 0x106:
            return asprintf(*event_name, "emulate_privop");
        case 0x007:
        case 0x107:
            return asprintf(*event_name, "emulate_4G");
        case 0x008:
        case 0x108:
            return asprintf(*event_name, "math_state_restore");
        case 0x009:
        case 0x109:
            return asprintf(*event_name, "paging_fixup");
        case 0x00a:
        case 0x10a:
            return asprintf(*event_name, "gdt_ldt_mapping_fault");
        case 0x00b:
        case 0x10b:
            return asprintf(*event_name, "ptwr_emulation");
        case 0x00c:
        case 0x10c:
            return asprintf(*event_name, "ptwr_emulation_pae");
        default:
            return 0;
    }
}

int get_pvcls_evinfo(const uint32_t event_id, const uint32_t *event_extra, char ***event_info)
{
    return 0;
}
