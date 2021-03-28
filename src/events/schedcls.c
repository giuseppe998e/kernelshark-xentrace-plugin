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

static int sched_min_evname(const uint32_t event_sub, char *result_str)
{
    switch (event_sub) {
        case 0x011:
            return sprintf(result_str, "running_to_runnable");
        case 0x021:
            return sprintf(result_str, "running_to_blocked");
        case 0x031:
            return sprintf(result_str, "running_to_offline");
        case 0x101:
            return sprintf(result_str, "runnable_to_running");
        case 0x121:
            return sprintf(result_str, "runnable_to_blocked");
        case 0x131:
            return sprintf(result_str, "runnable_to_offline");
        case 0x201:
            return sprintf(result_str, "blocked_to_running");
        case 0x211:
            return sprintf(result_str, "blocked_to_runnable");
        case 0x231:
            return sprintf(result_str, "blocked_to_offline");
        case 0x301:
            return sprintf(result_str, "offline_to_running");
        case 0x311:
            return sprintf(result_str, "offline_to_runnable");
        case 0x321:
            return sprintf(result_str, "offline_to_blocked");
        default:
            return 0;
    }
}

static int sched_verbs_evname(const uint32_t event_sub, char *result_str)
{
    switch (event_sub) {
        case 0x001:
            return sprintf(result_str, "sched_add_domain");
        case 0x002:
            return sprintf(result_str, "sched_rem_domain");
        case 0x003:
            return sprintf(result_str, "domain_sleep");
        case 0x004:
            return sprintf(result_str, "domain_wake");
        case 0x005:
            return sprintf(result_str, "do_yield");
        case 0x006:
            return sprintf(result_str, "do_block");
        case 0x007:
            return sprintf(result_str, "domain_shutdown");
        case 0x008:
            return sprintf(result_str, "sched_ctl");
        case 0x009:
            return sprintf(result_str, "sched_adjdom");
        case 0x00a:
            return sprintf(result_str, "__enter_scheduler");
        case 0x00b:
            return sprintf(result_str, "s_timer_fn");
        case 0x00c:
            return sprintf(result_str, "t_timer_fn");
        case 0x00d:
            return sprintf(result_str, "dom_timer_fn");
        case 0x00e:
            return sprintf(result_str, "switch_infprev");
        case 0x00f:
            return sprintf(result_str, "switch_infnext");
        case 0x010:
            return sprintf(result_str, "domain_shutdown_code");
        case 0x011:
            return sprintf(result_str, "switch_infcont");
        default:
            return 0;
    }
}

static int sched_class_evname(const uint32_t event_sub, char *result_str)
{
    switch (event_sub) {
        case 0x001:
            return sprintf(result_str, "csched:sched_tasklet");
        case 0x002:
            return sprintf(result_str, "csched:account_start");
        case 0x003:
            return sprintf(result_str, "csched:account_stop");
        case 0x004:
            return sprintf(result_str, "csched:stolen_vcpu");
        case 0x005:
            return sprintf(result_str, "csched:picked_cpu");
        case 0x006:
            return sprintf(result_str, "csched:tickle");
        case 0x007:
            return sprintf(result_str, "csched:boost");
        case 0x008:
            return sprintf(result_str, "csched:unboost");
        case 0x009:
            return sprintf(result_str, "csched:schedule");
        case 0x00A:
            return sprintf(result_str, "csched:ratelimit");
        case 0x00B:
            return sprintf(result_str, "csched:steal_check");
        case 0x201:
            return sprintf(result_str, "csched2:tick");
        case 0x202:
            return sprintf(result_str, "csched2:runq_pos");
        case 0x203:
            return sprintf(result_str, "csched2:credit_burn");
        case 0x204:
            return sprintf(result_str, "csched2:credit_add");
        case 0x205:
            return sprintf(result_str, "csched2:tickle_check"); // FIXME xentrace_format "format" file R#54
        case 0x206:
            return sprintf(result_str, "csched2:tickle");
        case 0x207:
            return sprintf(result_str, "csched2:credit_reset");
        case 0x208:
            return sprintf(result_str, "csched2:sched_tasklet");
        case 0x209:
            return sprintf(result_str, "csched2:update_load");
        case 0x20a:
            return sprintf(result_str, "csched2:runq_assign");
        case 0x20b:
            return sprintf(result_str, "csched2:updt_vcpu_load");
        case 0x20c:
            return sprintf(result_str, "csched2:updt_runq_load");
        case 0x20d:
            return sprintf(result_str, "csched2:tickle_new");
        case 0x20e:
            return sprintf(result_str, "csched2:runq_max_weight");
        case 0x20f:
            return sprintf(result_str, "csched2:migrrate");
        case 0x210:
            return sprintf(result_str, "csched2:load_check");
        case 0x211:
            return sprintf(result_str, "csched2:load_balance");
        case 0x212:
            return sprintf(result_str, "csched2:pick_cpu");
        case 0x213:
            return sprintf(result_str, "csched2:runq_candidate");
        case 0x214:
            return sprintf(result_str, "csched2:schedule");
        case 0x215:
            return sprintf(result_str, "csched2:ratelimit");
        case 0x216:
            return sprintf(result_str, "csched2:runq_cand_chk");
        case 0x801:
            return sprintf(result_str, "rtds:tickle");
        case 0x802:
            return sprintf(result_str, "rtds:runq_pick");
        case 0x803:
            return sprintf(result_str, "rtds:burn_budget");
        case 0x804:
            return sprintf(result_str, "rtds:repl_budget");
        case 0x805:
            return sprintf(result_str, "rtds:sched_tasklet");
        case 0x806:
            return sprintf(result_str, "rtds:schedule");
        case 0xA01:
            return sprintf(result_str, "null:pick_cpu");
        case 0xA02:
            return sprintf(result_str, "null:assign");
        case 0xA03:
            return sprintf(result_str, "null:deassign");
        case 0xA04:
            return sprintf(result_str, "null:migrate");
        case 0xA05:
            return sprintf(result_str, "null:schedule");
        case 0xA06:
            return sprintf(result_str, "null:sched_tasklet");
        default:
            return 0;
    }
}

int get_schedcls_evname(const uint32_t event_id, char *result_str)
{
    if (event_id == TRC_SCHED_CONTINUE_RUNNING)
        return sprintf(result_str, "continue_running");

    int event_sub = event_id & 0x00000fff;
    switch (GET_EVENT_SUBCLS(event_id)) {
        case GET_EVENT_SUBCLS(TRC_SCHED_MIN):
            return sched_min_evname(event_sub, result_str);
        case GET_EVENT_SUBCLS(TRC_SCHED_VERBOSE):
            return sched_verbs_evname(event_sub, result_str);
        case GET_EVENT_SUBCLS(TRC_SCHED_CLASS):
            return sched_class_evname(event_sub, result_str);
        default:
            return 0;
    }
}

//
// EVENT INFO
//

static int sched_min_evinfo(const uint32_t event_sub, 
                        const uint32_t *event_extra, char *result_str)
{
    return sprintf(result_str, "dom:vcpu = 0x%08x", event_extra[0]);
}

static int sched_verbs_evinfo(const uint32_t event_sub, 
                        const uint32_t *event_extra, char *result_str)
{
    switch (event_sub) {
        case 0x001:
        case 0x002:
        case 0x009:
            return sprintf(result_str, "domid = 0x%08x", event_extra[0]);
        case 0x003:
        case 0x004:
        case 0x005:
        case 0x006:
            return sprintf(result_str, "dom:vcpu = 0x%04x%04x", event_extra[0], event_extra[1]);
        case 0x007:
            return sprintf(result_str, "dom:vcpu = 0x%04x%04x, reason = 0x%08x", event_extra[0], event_extra[1], event_extra[2]);
        //case 0x008:
        //    return sprintf(result_str, "");
        case 0x00a:
            return sprintf(result_str, "prev<dom:vcpu> = 0x%04x%04x, next<dom:vcpu> = 0x%04x%04x", event_extra[0], event_extra[1], event_extra[2], event_extra[3]);
        //case 0x00b:
        //    return sprintf(result_str, "");
        //case 0x00c:
        //    return sprintf(result_str, "");
        //case 0x00d:
        //    return sprintf(result_str, "");
        case 0x00e:
            return sprintf(result_str, "dom:vcpu = 0x%04x%04x, runtime = %d", event_extra[0], event_extra[1], event_extra[2]);
        case 0x00f:
            return sprintf(result_str, "new_dom:vcpu = 0x%04x%04x, time = %d, r_time = %d", event_extra[0], event_extra[1], event_extra[2], event_extra[3]);
        case 0x010:
            return sprintf(result_str, "dom:vcpu = 0x%04x%04x, reason = 0x%08x", event_extra[0], event_extra[1], event_extra[2]);
        case 0x011:
            return sprintf(result_str, "dom:vcpu = 0x%04x%04x, runtime = %d, r_time = %d", event_extra[0], event_extra[1], event_extra[2], event_extra[3]);
        default:
            return 0;
    }
}

static int sched_class_evinfo(const uint32_t event_sub, 
                        const uint32_t *event_extra, char *result_str)
{
    switch (event_sub) {
        //case 0x001:
        //    return sprintf(result_str, "");
        case 0x002:
        case 0x003:
            return sprintf(result_str, "dom:vcpu = 0x%04x%04x, active = %d", event_extra[0], event_extra[1], event_extra[2]);
        case 0x004:
            return sprintf(result_str, "dom:vcpu = 0x%04x%04x, from = %d", event_extra[1], event_extra[2], event_extra[0]);
        case 0x005:
            return sprintf(result_str, "dom:vcpu = 0x%04x%04x, cpu = %d", event_extra[0], event_extra[1], event_extra[2]);
        case 0x006:
        case 0x206:
            return sprintf(result_str, "cpu = %d", event_extra[0]);
        case 0x007:
        case 0x008:
            return sprintf(result_str, "dom:vcpu = 0x%04x%04x", event_extra[0], event_extra[1]);
        case 0x009:
            return sprintf(result_str, "cpu[16]:tasklet[8]:idle[8] = %08x", event_extra[0]);
        case 0x00A:
        case 0x215:
            return sprintf(result_str, "dom:vcpu = 0x%08x, runtime = %d", event_extra[0], event_extra[1]);
        case 0x00B:
            return sprintf(result_str, "peer_cpu = %d, checked = %d", event_extra[0], event_extra[1]);

        //case 0x201:
        //    return sprintf(result_str, "");
        case 0x202:
            return sprintf(result_str, "[ dom:vcpu = 0x%08x, pos = %d]", event_extra[0], event_extra[1]);
        case 0x203:
            return sprintf(result_str, "burn [ dom:vcpu = 0x%08x, credit = %d, budget = %d, delta = %d ]", event_extra[0], event_extra[1], event_extra[2], event_extra[3]);
        //case 0x204:
        //    return sprintf(result_str, "");
        case 0x205:
            return sprintf(result_str, "dom:vcpu = 0x%08x, credit = %d, score = %d", event_extra[0], event_extra[1], event_extra[2]);
        case 0x207:
            return sprintf(result_str, "dom:vcpu = 0x%08x, cr_start = %d, cr_end = %d", event_extra[0], event_extra[1], event_extra[2]);
        //case 0x208:
        //    return sprintf(result_str, "");
        //case 0x209:
        //    return sprintf(result_str, "");
        case 0x20a:
            return sprintf(result_str, "dom:vcpu = 0x%08x, rq_id = %d", event_extra[0], event_extra[1]);
        case 0x20b:
            return sprintf(result_str, "dom:vcpu = 0x%08x, vcpuload = 0x%08x%08x, wshift = %d", event_extra[2], event_extra[1], event_extra[0], event_extra[3]);
        case 0x20c:
            return sprintf(result_str, "rq_load[16]:rq_id[8]:wshift[8] = 0x%08x, rq_avgload = 0x%08x%08x, b_avgload = 0x%08x%08x", event_extra[4], event_extra[1], event_extra[0], event_extra[3], event_extra[2]);
        case 0x20d:
            return sprintf(result_str, "dom:vcpu = 0x%08x, processor = %d credit = %d", event_extra[0], event_extra[1], event_extra[2]);
        case 0x20e:
            return sprintf(result_str, "rq_id[16]:max_weight[16] = 0x%08x", event_extra[0]);
        case 0x20f:
            return sprintf(result_str, "dom:vcpu = 0x%08x, rq_id[16]:trq_id[16] = 0x%08x", event_extra[0], event_extra[1]);
        case 0x210:
            return sprintf(result_str, "lrq_id[16]:orq_id[16] = 0x%08x, delta = %d", event_extra[0], event_extra[1]);
        case 0x211:
            return sprintf(result_str, "l_bavgload = 0x%08x%08x, o_bavgload = 0x%08x%08x, lrq_id[16]:orq_id[16] = 0x%08x", event_extra[1], event_extra[0], event_extra[3], event_extra[2], event_extra[4]);
        case 0x212:
            return sprintf(result_str, "b_avgload = 0x%08x%08x, dom:vcpu = 0x%08x, rq_id[16]:new_cpu[16] = %d", event_extra[1], event_extra[0], event_extra[2], event_extra[3]);
        case 0x213:
            return sprintf(result_str, "dom:vcpu = 0x%08x, credit = %d, tickled_cpu = %d", event_extra[0], event_extra[2], event_extra[1]);
        case 0x214:
            return sprintf(result_str, "rq:cpu = 0x%08x, tasklet[8]:idle[8]:smt_idle[8]:tickled[8] = %08x", event_extra[0], event_extra[1]);
        case 0x216:
            return sprintf(result_str, "dom:vcpu = 0x%08x", event_extra[0]);

        case 0x801:
            return sprintf(result_str, "cpu = %d", event_extra[0]);
        case 0x802:
        case 0x804:
            return sprintf(result_str, "dom:vcpu = 0x%08x, cur_deadline = 0x%08x%08x, cur_budget = 0x%08x%08x", event_extra[0], event_extra[2], event_extra[1], event_extra[4], event_extra[3]);
        case 0x803:
            return sprintf(result_str, "dom:vcpu = 0x%08x, cur_budget = 0x%08x%08x, delta = %d", event_extra[0], event_extra[2], event_extra[1], event_extra[3]);
        //case 0x805:
        //    return sprintf(result_str, "");
        case 0x806:
            return sprintf(result_str, "cpu[16]:tasklet[8]:idle[4]:tickled[4] = %08x", event_extra[0]);

        case 0xA01:
            return sprintf(result_str, "dom:vcpu = 0x%08x, new_cpu = %d", event_extra[0], event_extra[1]);
        case 0xA02:
        case 0xA03:
            return sprintf(result_str, "dom:vcpu = 0x%08x, cpu = %d", event_extra[0], event_extra[1]);
        case 0xA04:
            return sprintf(result_str, "dom:vcpu = 0x%08x, new_cpu:cpu = 0x%08x", event_extra[0], event_extra[1]);
        case 0xA05:
            return sprintf(result_str, "cpu[16]:tasklet[16] = %08x, dom:vcpu = 0x%08x", event_extra[0], event_extra[1]);
        //case 0xA06:
        //    return sprintf(result_str, "");
        default:
            return 0;
    }
}

int get_schedcls_evinfo(const uint32_t event_id,
                    const uint32_t *event_extra, char *result_str)
{
    int event_sub = event_id & 0x00000fff;
    switch (GET_EVENT_SUBCLS(event_id)) {
        case GET_EVENT_SUBCLS(TRC_SCHED_MIN):
            return sched_min_evinfo(event_sub, event_extra, result_str);
        case GET_EVENT_SUBCLS(TRC_SCHED_VERBOSE):
            return sched_verbs_evinfo(event_sub, event_extra, result_str);
        case GET_EVENT_SUBCLS(TRC_SCHED_CLASS):
            return sched_class_evinfo(event_sub, event_extra, result_str);
        default:
            return 0;
    }
}
