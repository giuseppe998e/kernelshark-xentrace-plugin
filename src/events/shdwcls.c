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

int get_shdwcls_evname(const uint32_t event_id, char *result_str)
{
    int event_sub = event_id & 0x00000fff;
    switch (event_sub) {
        case 0x001:
        case 0x101:
            return EVNAME(result_str, "shadow_not_shadow");
        case 0x002:
        case 0x102:
            return EVNAME(result_str, "shadow_fast_propagate");
        case 0x003:
        case 0x103:
            return EVNAME(result_str, "shadow_fast_mmio");
        case 0x004:
        case 0x104:
            return EVNAME(result_str, "shadow_false_fast_path");
        case 0x005:
        case 0x105:
            return EVNAME(result_str, "shadow_mmio");
        case 0x006:
        case 0x106:
            return EVNAME(result_str, "shadow_fixup");
        case 0x007:
        case 0x107:
            return EVNAME(result_str, "shadow_domf_dying");
        case 0x008:
        case 0x108:
            return EVNAME(result_str, "shadow_emulate");
        case 0x009:
        case 0x109:
            return EVNAME(result_str, "shadow_emulate_unshadow_user");
        case 0x00a:
        case 0x10a:
            return EVNAME(result_str, "shadow_emulate_unshadow_evtinj");
        case 0x00b:
        case 0x10b:
            return EVNAME(result_str, "shadow_emulate_unshadow_unhandled");
        case 0x00c:
        case 0x10c:
            return EVNAME(result_str, "shadow_emulate_wrmap_bf");
        case 0x00d:
        case 0x10d:
            return EVNAME(result_str, "shadow_emulate_prealloc_unpin");
        case 0x00e:
        case 0x10e:
            return EVNAME(result_str, "shadow_emulate_resync_full");
        case 0x00f:
        case 0x10f:
            return EVNAME(result_str, "shadow_emulate_resync_only");
        default:
            return 0;
    }
}

//
// EVENT INFO
//

int get_shdwcls_evinfo(const uint32_t event_id,
                    const uint32_t *event_extra, char *result_str)
{
    int event_sub = event_id & 0x00000fff;
    switch (event_sub) {
        case 0x001:
            return EVINFO(result_str, "gl1e = 0x%08x%08x, va = 0x%08x, flags = 0x%08x", event_extra[1], event_extra[0], event_extra[2], event_extra[4]);
        case 0x101:
        case 0x106:
            return EVINFO(result_str, "gl1e = 0x%08x%08x, va = 0x%08x%08x, flags = 0x%08x", event_extra[1], event_extra[0], event_extra[3], event_extra[2], event_extra[4]);
        case 0x002:
        case 0x003:
        case 0x004:
        case 0x005:
        case 0x007:
            return EVINFO(result_str, "va = 0x%08x", event_extra[0]);
        case 0x102:
        case 0x103:
        case 0x104:
        case 0x105:
        case 0x107:
            return EVINFO(result_str, "va = 0x%08x%08x", event_extra[1], event_extra[0]);
        case 0x006:
            return EVINFO(result_str, "gl1e = 0x%08x, va = 0x%08x, flags = 0x%08x", event_extra[0], event_extra[1], event_extra[2]);
        case 0x008:
            return EVINFO(result_str, "gl1e = 0x%08x, write_val = 0x%08x, va = 0x%08x, flags = 0x%08x", event_extra[0], event_extra[1], event_extra[2], event_extra[3]);
        case 0x108:
            return EVINFO(result_str, "gl1e = 0x%08x%08x, write_val = 0x%08x%08x, va = 0x%08x%08x, flags = 0x%08x", event_extra[1], event_extra[0], event_extra[3], event_extra[2], event_extra[5], event_extra[4], event_extra[6]);
        case 0x009:
        case 0x00a:
        case 0x00b:
            return EVINFO(result_str, "va = 0x%08x, gfn = 0x%08x", event_extra[0], event_extra[1]);
        case 0x109:
        case 0x10a:
        case 0x10b:
            return EVINFO(result_str, "va = 0x%08x%08x, gfn = 0x%08x%08x", event_extra[1], event_extra[0], event_extra[3], event_extra[2]);
        case 0x00c:
        case 0x00d:
        case 0x00e:
        case 0x00f:
            return EVINFO(result_str, "gfn = 0x%08x", event_extra[0]);
        case 0x10c:
        case 0x10d:
        case 0x10e:
        case 0x10f:
            return EVINFO(result_str, "gfn = 0x%08x%08x", event_extra[1], event_extra[0]);
        default:
            return 0;
    }
}

