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

static int sched_min_evname(const uint32_t event_sub, char ***event_name)
{
    switch (event_sub) {
        case 0x011:
            return asprintf(*event_name, "running_to_runnable");
        case 0x021:
            return asprintf(*event_name, "running_to_blocked");
        case 0x031:
            return asprintf(*event_name, "running_to_offline");
        case 0x101:
            return asprintf(*event_name, "runnable_to_running");
        case 0x121:
            return asprintf(*event_name, "runnable_to_blocked");
        case 0x131:
            return asprintf(*event_name, "runnable_to_offline");
        case 0x201:
            return asprintf(*event_name, "blocked_to_running");
        case 0x211:
            return asprintf(*event_name, "blocked_to_runnable");
        case 0x231:
            return asprintf(*event_name, "blocked_to_offline");
        case 0x301:
            return asprintf(*event_name, "offline_to_running");
        case 0x311:
            return asprintf(*event_name, "offline_to_runnable");
        case 0x321:
            return asprintf(*event_name, "offline_to_blocked");
        default:
            return 0;
    }
}

static int sched_verbs_evname(const uint32_t event_sub, char ***event_name)
{
    switch (event_sub) {
        case 0x001:
            return asprintf(*event_name, "sched_add_domain");
        case 0x002:
            return asprintf(*event_name, "sched_rem_domain");
        case 0x003:
            return asprintf(*event_name, "domain_sleep");
        case 0x004:
            return asprintf(*event_name, "domain_wake");
        case 0x005:
            return asprintf(*event_name, "do_yield");
        case 0x006:
            return asprintf(*event_name, "do_block");
        case 0x007:
            return asprintf(*event_name, "domain_shutdown");
        case 0x008:
            return asprintf(*event_name, "sched_ctl");
        case 0x009:
            return asprintf(*event_name, "sched_adjdom");
        case 0x00a:
            return asprintf(*event_name, "__enter_scheduler");
        case 0x00b:
            return asprintf(*event_name, "s_timer_fn");
        case 0x00c:
            return asprintf(*event_name, "t_timer_fn");
        case 0x00d:
            return asprintf(*event_name, "dom_timer_fn");
        case 0x00e:
            return asprintf(*event_name, "switch_infprev");
        case 0x00f:
            return asprintf(*event_name, "switch_infnext");
        case 0x010:
            return asprintf(*event_name, "domain_shutdown_code");
        case 0x011:
            return asprintf(*event_name, "switch_infcont");
        default:
            return 0;
    }
}

static int sched_class_evname(const uint32_t event_sub, char ***event_name)
{
    switch (event_sub) {
        case 0x001:
            return asprintf(*event_name, "csched:sched_tasklet");
        case 0x002:
            return asprintf(*event_name, "csched:account_start");
        case 0x003:
            return asprintf(*event_name, "csched:account_stop");
        case 0x004:
            return asprintf(*event_name, "csched:stolen_vcpu");
        case 0x005:
            return asprintf(*event_name, "csched:picked_cpu");
        case 0x006:
            return asprintf(*event_name, "csched:tickle");
        case 0x007:
            return asprintf(*event_name, "csched:boost");
        case 0x008:
            return asprintf(*event_name, "csched:unboost");
        case 0x009:
            return asprintf(*event_name, "csched:schedule");
        case 0x00A:
            return asprintf(*event_name, "csched:ratelimit");
        case 0x00B:
            return asprintf(*event_name, "csched:steal_check");
        case 0x201:
            return asprintf(*event_name, "csched2:tick");
        case 0x202:
            return asprintf(*event_name, "csched2:runq_pos");
        case 0x203:
            return asprintf(*event_name, "csched2:credit_burn");
        case 0x204:
            return asprintf(*event_name, "csched2:credit_add");
        case 0x205:
            return asprintf(*event_name, "csched2:tickle_check"); // FIXME xentrace_format "format" file R#54
        case 0x206:
            return asprintf(*event_name, "csched2:tickle");
        case 0x207:
            return asprintf(*event_name, "csched2:credit_reset");
        case 0x208:
            return asprintf(*event_name, "csched2:sched_tasklet");
        case 0x209:
            return asprintf(*event_name, "csched2:update_load");
        case 0x20a:
            return asprintf(*event_name, "csched2:runq_assign");
        case 0x20b:
            return asprintf(*event_name, "csched2:updt_vcpu_load");
        case 0x20c:
            return asprintf(*event_name, "csched2:updt_runq_load");
        case 0x20d:
            return asprintf(*event_name, "csched2:tickle_new");
        case 0x20e:
            return asprintf(*event_name, "csched2:runq_max_weight");
        case 0x20f:
            return asprintf(*event_name, "csched2:migrrate");
        case 0x210:
            return asprintf(*event_name, "csched2:load_check");
        case 0x211:
            return asprintf(*event_name, "csched2:load_balance");
        case 0x212:
            return asprintf(*event_name, "csched2:pick_cpu");
        case 0x213:
            return asprintf(*event_name, "csched2:runq_candidate");
        case 0x214:
            return asprintf(*event_name, "csched2:schedule");
        case 0x215:
            return asprintf(*event_name, "csched2:ratelimit");
        case 0x216:
            return asprintf(*event_name, "csched2:runq_cand_chk");
        case 0x801:
            return asprintf(*event_name, "rtds:tickle");
        case 0x802:
            return asprintf(*event_name, "rtds:runq_pick");
        case 0x803:
            return asprintf(*event_name, "rtds:burn_budget");
        case 0x804:
            return asprintf(*event_name, "rtds:repl_budget");
        case 0x805:
            return asprintf(*event_name, "rtds:sched_tasklet");
        case 0x806:
            return asprintf(*event_name, "rtds:schedule");
        case 0xA01:
            return asprintf(*event_name, "null:pick_cpu");
        case 0xA02:
            return asprintf(*event_name, "null:assign");
        case 0xA03:
            return asprintf(*event_name, "null:deassign");
        case 0xA04:
            return asprintf(*event_name, "null:migrate");
        case 0xA05:
            return asprintf(*event_name, "null:schedule");
        case 0xA06:
            return asprintf(*event_name, "null:sched_tasklet");
        default:
            return 0;
    }
}

int get_schedcls_evname(const uint32_t event_id, char ***event_name)
{
    if (event_id == TRC_SCHED_CONTINUE_RUNNING)
        return asprintf(*event_name, "continue_running");

    int event_sub = event_id & 0x00000fff;
    switch (GET_EVENT_SUBCLS(event_id)) {
        case GET_EVENT_SUBCLS(TRC_SCHED_MIN):
            return sched_min_evname(event_sub, event_name);
        case GET_EVENT_SUBCLS(TRC_SCHED_VERBOSE):
            return sched_verbs_evname(event_sub, event_name);
        case GET_EVENT_SUBCLS(TRC_SCHED_CLASS):
            return sched_class_evname(event_sub, event_name);
        default:
            return 0;
    }
}

int get_schedcls_evinfo(const uint32_t event_id, const uint32_t *event_extra, char ***event_info)
{
    return 0;
}
