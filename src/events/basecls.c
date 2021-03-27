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

int get_basecls_evname(const uint32_t event_id, char ***event_name)
{
    switch (event_id) {
        case TRC_TRACE_WRAP_BUFFER:
            return asprintf(*event_name, "wrap_buffer");
        case TRC_LOST_RECORDS:
            return asprintf(*event_name, "lost_records");
        case (TRC_GEN | 0x004):
            return asprintf(*event_name, "trace_irq");
        //case TRC_LOST_RECORDS_END:
        //    return asprintf(&event_name, "lost_records_end");
        default:
            return 0;
    }
}

int get_basecls_evinfo(const uint32_t event_id, const uint32_t *event_extra, char ***event_info)
{
    switch (event_id) {
        case TRC_TRACE_WRAP_BUFFER:
            return 0;
        case TRC_LOST_RECORDS:
            return 0;
        //case TRC_LOST_RECORDS_END:
        //    return 0;
        default:
            return 0;
    }
}