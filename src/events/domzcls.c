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

int get_dom0cls_evname(const uint32_t event_id, char ***event_name)
{
    int event_sub = event_id & 0x00000fff;
    switch (event_sub) {
        case 0x001:
            return asprintf(*event_name, "domain_create");
        case 0x002:
            return asprintf(*event_name, "domain_destroy");
        default:
            return 0;
    }
}

int get_dom0cls_evinfo(const uint32_t event_id, const uint32_t *event_extra, char ***event_info)
{
    return 0;
}
