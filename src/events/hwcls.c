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

static int hw_pm_evname(const uint32_t event_sub, char *result_str)
{
    switch (event_sub) {
        case 0x001:
            return sprintf(result_str, "cpu_freq_change");
        case 0x002:
            return sprintf(result_str, "cpu_idle_entry");
        case 0x003:
            return sprintf(result_str, "cpu_idle_exit");
        default:
            return 0;
    }
}

static int hw_irq_evname(const uint32_t event_sub, char *result_str)
{
    switch (event_sub) {
        case 0x001:
            return sprintf(result_str, "cleanup_move_delayed");
        case 0x002:
            return sprintf(result_str, "cleanup_move");
        case 0x003:
            return sprintf(result_str, "bind_vector");
        case 0x004:
            return sprintf(result_str, "clear_vector");
        case 0x005:
            return sprintf(result_str, "move_vector");
        case 0x006:
            return sprintf(result_str, "assign_vector");
        case 0x007:
            return sprintf(result_str, "bogus_vector");
        case 0x008:
            return sprintf(result_str, "do_irq");
        default:
            return 0;
    }
}

int get_hwcls_evname(const uint32_t event_id, char *result_str)
{
    int event_sub = event_id & 0x00000fff;
    switch (GET_EVENT_SUBCLS(event_id)) {
        case GET_EVENT_SUBCLS(TRC_HW_PM):
            return hw_pm_evname(event_sub, result_str);
        case GET_EVENT_SUBCLS(TRC_HW_IRQ):
            return hw_irq_evname(event_sub, result_str);
        default:
            return 0;
    }
}

//
// EVENT INFO
//

static int hw_pm_evinfo(const uint32_t event_sub,
                const uint32_t *event_extra, char *result_str)
{
    switch (event_sub) {
        case 0x001:
            return sprintf(result_str, "%dMHz -> %dMHz", event_extra[0], event_extra[1]);
        case 0x002:
            return sprintf(result_str, "C0 -> C%d, acpi_pm_tick = %d, expected = %dus, predicted = %dus",
                                event_extra[0], event_extra[1], event_extra[2], event_extra[3]);
        case 0x003:
            return sprintf(result_str, "C%d -> C0, acpi_pm_tick = %d, irq = %d %d %d %d",
                                event_extra[0], event_extra[1], event_extra[2], event_extra[3],
                                event_extra[4], event_extra[5]);
        default:
            return 0;
    }
}

static int hw_irq_evinfo(const uint32_t event_sub,
                const uint32_t *event_extra, char *result_str)
{
    switch (event_sub) {
        case 0x001:
        case 0x002:
            return sprintf(result_str, "irq = %d, vector 0x%x on CPU%d", event_extra[0],
                                event_extra[1], event_extra[2]);
        case 0x003:
        case 0x004:
        case 0x006:
            return sprintf(result_str, "irq = %d = vector 0x%x, CPU mask: 0x%08x",
                                event_extra[0], event_extra[1], event_extra[2]);
        case 0x005:
            return sprintf(result_str, "irq = %d had vector 0x%x on CPU%d", event_extra[0],
                                event_extra[1], event_extra[2]);
        case 0x007:
            return sprintf(result_str, "0x%x", event_extra[0]);
        case 0x008:
            return sprintf(result_str, "irq = %d, began = %dus, ended = %dus", event_extra[0],
                                event_extra[1], event_extra[2]);
        default:
            return 0;
    }
}

int get_hwcls_evinfo(const uint32_t event_id,
                const uint32_t *event_extra, char *result_str)
{
    int event_sub = event_id & 0x00000fff;
    switch (GET_EVENT_SUBCLS(event_id)) {
        case GET_EVENT_SUBCLS(TRC_HW_PM):
            return hw_pm_evinfo(event_sub, event_extra, result_str);
        case GET_EVENT_SUBCLS(TRC_HW_IRQ):
            return hw_irq_evinfo(event_sub, event_extra, result_str);
        default:
            return 0;
    }
}
