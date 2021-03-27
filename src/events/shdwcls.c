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

int get_shdwcls_evname(const uint32_t event_id, char ***event_name)
{
    int event_sub = event_id & 0x00000fff;
    switch (event_sub) {
        case 0x001:
        case 0x101:
            return asprintf(*event_name, "shadow_not_shadow");
        case 0x002:
        case 0x102:
            return asprintf(*event_name, "shadow_fast_propagate");
        case 0x003:
        case 0x103:
            return asprintf(*event_name, "shadow_fast_mmio");
        case 0x004:
        case 0x104:
            return asprintf(*event_name, "shadow_false_fast_path");
        case 0x005:
        case 0x105:
            return asprintf(*event_name, "shadow_mmio");
        case 0x006:
        case 0x106:
            return asprintf(*event_name, "shadow_fixup");
        case 0x007:
        case 0x107:
            return asprintf(*event_name, "shadow_domf_dying");
        case 0x008:
        case 0x108:
            return asprintf(*event_name, "shadow_emulate");
        case 0x009:
        case 0x109:
            return asprintf(*event_name, "shadow_emulate_unshadow_user");
        case 0x00a:
        case 0x10a:
            return asprintf(*event_name, "shadow_emulate_unshadow_evtinj");
        case 0x00b:
        case 0x10b:
            return asprintf(*event_name, "shadow_emulate_unshadow_unhandled");
        case 0x00c:
        case 0x10c:
            return asprintf(*event_name, "shadow_emulate_wrmap_bf");
        case 0x00d:
        case 0x10d:
            return asprintf(*event_name, "shadow_emulate_prealloc_unpin");
        case 0x00e:
        case 0x10e:
            return asprintf(*event_name, "shadow_emulate_resync_full");
        case 0x00f:
        case 0x10f:
            return asprintf(*event_name, "shadow_emulate_resync_only");
        default:
            return 0;
    }
}

int get_shdwcls_evinfo(const uint32_t event_id, const uint32_t *event_extra, char ***event_info)
{
    return 0;
}

