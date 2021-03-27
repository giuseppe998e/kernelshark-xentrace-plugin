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

static int hw_pm_evname(const uint32_t event_sub, char ***event_name)
{
    switch (event_sub) {
        case 0x001:
            return asprintf(*event_name, "cpu_freq_change");
        case 0x002:
            return asprintf(*event_name, "cpu_idle_entry");
        case 0x003:
            return asprintf(*event_name, "cpu_idle_exit");
        default:
            return 0;
    }
}

static int hw_irq_evname(const uint32_t event_sub, char ***event_name)
{
    switch (event_sub) {
        case 0x001:
            return asprintf(*event_name, "cleanup_move_delayed");
        case 0x002:
            return asprintf(*event_name, "cleanup_move");
        case 0x003:
            return asprintf(*event_name, "bind_vector");
        case 0x004:
            return asprintf(*event_name, "clear_vector");
        case 0x005:
            return asprintf(*event_name, "move_vector");
        case 0x006:
            return asprintf(*event_name, "assign_vector");
        case 0x007:
            return asprintf(*event_name, "bogus_vector");
        case 0x008:
            return asprintf(*event_name, "do_irq");
        default:
            return 0;
    }
}

int get_hwcls_evname(const uint32_t event_id, char ***event_name)
{
    int event_sub = event_id & 0x00000fff;
    switch (GET_EVENT_SUBCLS(event_id)) {
        case GET_EVENT_SUBCLS(TRC_HW_PM):
            return hw_pm_evname(event_sub, event_name);
        case GET_EVENT_SUBCLS(TRC_HW_IRQ):
            return hw_irq_evname(event_sub, event_name);
        default:
            return 0;
    }
}

int get_hwcls_evinfo(const uint32_t event_id, const uint32_t *event_extra, char ***event_info)
{
    return 0;
}
