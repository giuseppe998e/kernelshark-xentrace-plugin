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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// KernelShark.v2-Beta
#include "libkshark.h"
#include "libkshark-plugin.h"
// Xen Project
#include "trace.h"
// XenTrace-Parser
#include "xentrace-event.h"
#include "xentrace-parser.h"
// Events formatting
#include "events/events.h"

#define ENV_XEN_CPUHZ "XEN_CPUHZ"
#define ENV_XEN_ABSTS "XEN_ABSTS"

#define DEFAULT_CPU_HZ 2400000000LL
#define QHZ_FROM_HZ(_hz) (((_hz) << 10) / 1000000000)

static const char *format_name = "xentrace_binary";

// Plugin instance variables
static struct {
    // XenTrace Parser instance.
    xentrace_parser parser;
    // CPU Hz and Qhz values to use
    // with the currently open trace.
    uint64_t cpu_hz,
            cpu_qhz;
    // First TSC value readed in
    // currently open trace.
    // Used for relative timestamp.
    uint64_t first_tsc;
} I;

/**
 * 
 */
static const int get_pid(struct kshark_data_stream *stream,
                            const struct kshark_entry *entry)
{
    if (entry->visible & KS_PLUGIN_UNTOUCHED_MASK)
        return entry->pid;

    return KS_EMPTY_BIN;
}

/**
 * 
 */
static char *get_task(struct kshark_data_stream *stream,
                        const struct kshark_entry *entry)
{
    xt_event *event = xtp_get_event(I.parser, entry->offset);
    if (!event)
        return NULL;

    xt_header *hdr = &event->hdr;
    char *task_str;
    int ret = (hdr->dom == XEN_DOM_IDLE) ?
                asprintf(&task_str, "idle/v%u", hdr->vcpu) :
                    asprintf(&task_str, "d%u/v%u", hdr->dom, hdr->vcpu);

    if (ret <= 0)
        return NULL;

    return task_str;
}

/**
 * 
 */
static char *get_event_name(struct kshark_data_stream *stream,
                            const struct kshark_entry *entry)
{
    xt_event *event = xtp_get_event(I.parser, entry->offset);
    if (!event)
        return NULL;

    uint32_t event_id = (event->rec).id;
    char **event_name;
    int success;

    switch ( GET_EVENT_CLS(event_id) ) {
        // General trace
        case GET_EVENT_CLS(TRC_GEN):
            success = get_basecls_evname(event_id, &event_name);
            break;
        // Xen Scheduler trace
        case GET_EVENT_CLS(TRC_SCHED):
            success = get_schedcls_evname(event_id, &event_name);
            break;
        // Xen DOM0 operation trace
        case GET_EVENT_CLS(TRC_DOM0OP):
            success = get_dom0cls_evname(event_id, &event_name);
            break;
        // Xen HVM trace
        case GET_EVENT_CLS(TRC_HVM):
            success = get_hvmcls_evname(event_id, &event_name);
            break;
        // Xen memory trace
        case GET_EVENT_CLS(TRC_MEM):
            success = get_memcls_evname(event_id, &event_name);
            break;
        // Xen PV traces
        case GET_EVENT_CLS(TRC_PV):
            success = get_pvcls_evname(event_id, &event_name);
            break;
        // Xen shadow tracing
        case GET_EVENT_CLS(TRC_SHADOW):
            success = get_shdwcls_evname(event_id, &event_name);
            break;
        // Xen hardware-related traces
        case GET_EVENT_CLS(TRC_HW):
            success = get_hwcls_evname(event_id, &event_name);
            break;
    }

    if (success < 1) {
        success = asprintf(event_name, "Unknown (0x%08x)", event_id);
        if (success < 1)
            return NULL;
    }

    return *event_name;
}

/**
 * 
 */
static char *get_info(struct kshark_data_stream *stream,
                        const struct kshark_entry *entry)
{
    xt_event *event = xtp_get_event(I.parser, entry->offset);
    if (!event)
        return NULL;

    xt_record *rec = &event->rec;
    char *info_str;
    int ret = 0;

    switch (rec->id) {
        case (TRC_GEN | 0x001):
            ret = asprintf(&info_str, "0x%08x", rec->extra[0]);
            break;
        case (TRC_GEN | 0x002):
            ret = asprintf(&info_str, "0x%08x", rec->extra[0]);
            break;
        case (TRC_GEN | 0x003):
            ret = asprintf(&info_str, "0x%08x", rec->extra[0]);
            break;
        case (TRC_GEN | 0x004):
            ret = asprintf(&info_str, "vector = %d, count = %d, tot_cycles = 0x%08x, max_cycles = 0x%08x", rec->extra[0], rec->extra[1], rec->extra[2], rec->extra[3]);
            break;

        case (TRC_SCHED_MIN | 0x002):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_MIN | 0x011):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_MIN | 0x021):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_MIN | 0x031):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_MIN | 0x101):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_MIN | 0x121):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_MIN | 0x131):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_MIN | 0x201):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_MIN | 0x211):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_MIN | 0x231):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_MIN | 0x301):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_MIN | 0x311):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_MIN | 0x321):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;

        case (TRC_SCHED_VERBOSE | 0x001):
            ret = asprintf(&info_str, "domid = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_VERBOSE | 0x002):
            ret = asprintf(&info_str, "domid = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_VERBOSE | 0x003):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_VERBOSE | 0x004):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_VERBOSE | 0x005):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_VERBOSE | 0x006):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_VERBOSE | 0x007):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x, reason = 0x%08x", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        //case (TRC_SCHED_VERBOSE | 0x008):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_SCHED_VERBOSE | 0x009):
            ret = asprintf(&info_str, "domid = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_VERBOSE | 0x00a):
            ret = asprintf(&info_str, "prev<dom:vcpu> = 0x%04x%04x, next<dom:vcpu> = 0x%04x%04x", rec->extra[0], rec->extra[1], rec->extra[2], rec->extra[3]);
            break;
        //case (TRC_SCHED_VERBOSE | 0x00b):
        //    ret = asprintf(&info_str, "");
        //    break;
        //case (TRC_SCHED_VERBOSE | 0x00c):
        //    ret = asprintf(&info_str, "");
        //    break;
        //case (TRC_SCHED_VERBOSE | 0x00d):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_SCHED_VERBOSE | 0x00e):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x, runtime = %d", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_SCHED_VERBOSE | 0x00f):
            ret = asprintf(&info_str, "new_dom:vcpu = 0x%04x%04x, time = %d, r_time = %d", rec->extra[0], rec->extra[1], rec->extra[2], rec->extra[3]);
            break;
        case (TRC_SCHED_VERBOSE | 0x010):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x, reason = 0x%08x", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_SCHED_VERBOSE | 0x011):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x, runtime = %d, r_time = %d", rec->extra[0], rec->extra[1], rec->extra[2], rec->extra[3]);
            break;

        //case (TRC_SCHED_CLASS | 0x001):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_SCHED_CLASS | 0x002):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x, active = %d", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_SCHED_CLASS | 0x003):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x, active = %d", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_SCHED_CLASS | 0x004):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x, from = %d", rec->extra[1], rec->extra[2], rec->extra[0]);
            break;
        case (TRC_SCHED_CLASS | 0x005):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x, cpu = %d", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_SCHED_CLASS | 0x006):
            ret = asprintf(&info_str, "cpu = %d", rec->extra[0]);
            break;
        case (TRC_SCHED_CLASS | 0x007):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0x008):
            ret = asprintf(&info_str, "dom:vcpu = 0x%04x%04x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0x009):
            ret = asprintf(&info_str, "cpu[16]:tasklet[8]:idle[8] = %08x", rec->extra[0]);
            break;
        case (TRC_SCHED_CLASS | 0x00A):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, runtime = %d", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0x00B):
            ret = asprintf(&info_str, "peer_cpu = %d, checked = %d", rec->extra[0], rec->extra[1]);
            break;

        //case (TRC_SCHED_CLASS | 0x201):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_SCHED_CLASS | 0x202):
            ret = asprintf(&info_str, "[ dom:vcpu = 0x%08x, pos = %d]", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0x203):
            ret = asprintf(&info_str, "burn    [ dom:vcpu = 0x%08x, credit = %d, budget = %d, delta = %d ]", rec->extra[0], rec->extra[1], rec->extra[2], rec->extra[3]);
            break;
        //case (TRC_SCHED_CLASS | 0x204):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_SCHED_CLASS | 0x205):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, credit = %d, score = %d", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_SCHED_CLASS | 0x206):
            ret = asprintf(&info_str, "cpu = %d", rec->extra[0]);
            break;
        case (TRC_SCHED_CLASS | 0x207):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, cr_start = %d, cr_end = %d", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        //case (TRC_SCHED_CLASS | 0x208):
        //    ret = asprintf(&info_str, "");
        //    break;
        //case (TRC_SCHED_CLASS | 0x209):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_SCHED_CLASS | 0x20a):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, rq_id = %d", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0x20b):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, vcpuload = 0x%08x%08x, wshift = %d", rec->extra[2], rec->extra[1], rec->extra[0], rec->extra[3]);
            break;
        case (TRC_SCHED_CLASS | 0x20c):
            ret = asprintf(&info_str, "rq_load[16]:rq_id[8]:wshift[8] = 0x%08x, rq_avgload = 0x%08x%08x, b_avgload = 0x%08x%08x", rec->extra[4], rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2]);
            break;
        case (TRC_SCHED_CLASS | 0x20d):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, processor = %d credit = %d", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_SCHED_CLASS | 0x20e):
            ret = asprintf(&info_str, "rq_id[16]:max_weight[16] = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SCHED_CLASS | 0x20f):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, rq_id[16]:trq_id[16] = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0x210):
            ret = asprintf(&info_str, "lrq_id[16]:orq_id[16] = 0x%08x, delta = %d", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0x211):
            ret = asprintf(&info_str, "l_bavgload = 0x%08x%08x, o_bavgload = 0x%08x%08x, lrq_id[16]:orq_id[16] = 0x%08x", rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2], rec->extra[4]);
            break;
        case (TRC_SCHED_CLASS | 0x212):
            ret = asprintf(&info_str, "b_avgload = 0x%08x%08x, dom:vcpu = 0x%08x, rq_id[16]:new_cpu[16] = %d", rec->extra[1], rec->extra[0], rec->extra[2], rec->extra[3]);
            break;
        case (TRC_SCHED_CLASS | 0x213):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, credit = %d, tickled_cpu = %d", rec->extra[0], rec->extra[2], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0x214):
            ret = asprintf(&info_str, "rq:cpu = 0x%08x, tasklet[8]:idle[8]:smt_idle[8]:tickled[8] = %08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0x215):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, runtime = %d", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0x216):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x", rec->extra[0]);
            break;

        case (TRC_SCHED_CLASS | 0x801):
            ret = asprintf(&info_str, "cpu = %d", rec->extra[0]);
            break;
        case (TRC_SCHED_CLASS | 0x802):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, cur_deadline = 0x%08x%08x, cur_budget = 0x%08x%08x", rec->extra[0], rec->extra[2], rec->extra[1], rec->extra[4], rec->extra[3]);
            break;
        case (TRC_SCHED_CLASS | 0x803):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, cur_budget = 0x%08x%08x, delta = %d", rec->extra[0], rec->extra[2], rec->extra[1], rec->extra[3]);
            break;
        case (TRC_SCHED_CLASS | 0x804):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, cur_deadline = 0x%08x%08x, cur_budget = 0x%08x%08x", rec->extra[0], rec->extra[2], rec->extra[1], rec->extra[4], rec->extra[3]);
            break;
        //case (TRC_SCHED_CLASS | 0x805):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_SCHED_CLASS | 0x806):
            ret = asprintf(&info_str, "cpu[16]:tasklet[8]:idle[4]:tickled[4] = %08x", rec->extra[0]);
            break;

        case (TRC_SCHED_CLASS | 0xA01):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, new_cpu = %d", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0xA02):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, cpu = %d", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0xA03):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, cpu = %d", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0xA04):
            ret = asprintf(&info_str, "dom:vcpu = 0x%08x, new_cpu:cpu = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SCHED_CLASS | 0xA05):
            ret = asprintf(&info_str, "cpu[16]:tasklet[16] = %08x, dom:vcpu = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        //case (TRC_SCHED_CLASS | 0xA06):
        //    ret = asprintf(&info_str, "");
        //    break;

        case (TRC_DOM0_DOMOPS | 0x001):
            ret = asprintf(&info_str, "dom = 0x%08x", rec->extra[0]);
            break;
        case (TRC_DOM0_DOMOPS | 0x002):
            ret = asprintf(&info_str, "dom = 0x%08x", rec->extra[0]);
            break;

        //case (TRC_HVM_ENTRYEXIT | 0x001):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_HVM_ENTRYEXIT | 0x002):
            ret = asprintf(&info_str, "exitcode = 0x%08x, rIP  = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_ENTRYEXIT | 0x102):
            ret = asprintf(&info_str, "exitcode = 0x%08x, rIP  = 0x%08x%08x", rec->extra[0], rec->extra[2], rec->extra[1]);
            break;
        //case (TRC_HVM_ENTRYEXIT | 0x401):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_HVM_ENTRYEXIT | 0x402):
            ret = asprintf(&info_str, "exitcode = 0x%08x, rIP  = 0x%08x", rec->extra[0], rec->extra[2]);
            break;
        case (TRC_HVM_ENTRYEXIT | 0x502):
            ret = asprintf(&info_str, "exitcode = 0x%08x, rIP  = 0x%08x%08x", rec->extra[0], rec->extra[2], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x001):
            ret = asprintf(&info_str, "errorcode = 0x%02x, virt = 0x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_HVM_HANDLER | 0x101):
            ret = asprintf(&info_str, "errorcode = 0x%02x, virt = 0x%08x%08x", rec->extra[2], rec->extra[1], rec->extra[0]);
            break;
        case (TRC_HVM_HANDLER | 0x002):
            ret = asprintf(&info_str, "errorcode = 0x%02x, virt = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x102):
            ret = asprintf(&info_str, "errorcode = 0x%02x, virt = 0x%08x%08x", rec->extra[0], rec->extra[2], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x003):
            ret = asprintf(&info_str, "vector = 0x%02x, errorcode = 0x%04x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x004):
            ret = asprintf(&info_str, "vector = 0x%02x, fake = %d", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x005):
            ret = asprintf(&info_str, "vector = 0x%02x", rec->extra[0]);
            break;
        case (TRC_HVM_HANDLER | 0x006):
            ret = asprintf(&info_str, "port = 0x%04x, size = %d", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x007):
            ret = asprintf(&info_str, "port = 0x%04x, size = %d", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x008):
            ret = asprintf(&info_str, "CR# = %d, value = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x108):
            ret = asprintf(&info_str, "CR# = %d, value = 0x%08x%08x", rec->extra[0], rec->extra[2], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x009):
            ret = asprintf(&info_str, "CR# = %d, value = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x109):
            ret = asprintf(&info_str, "CR# = %d, value = 0x%08x%08x", rec->extra[0], rec->extra[2], rec->extra[1]);
            break;
        //case (TRC_HVM_HANDLER | 0x00A):
        //    ret = asprintf(&info_str, "");
        //    break;
        //case (TRC_HVM_HANDLER | 0x00B):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_HVM_HANDLER | 0x00C):
            ret = asprintf(&info_str, "MSR# = 0x%08x, value = 0x%08x%08x", rec->extra[0], rec->extra[2], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x00D):
            ret = asprintf(&info_str, "MSR# = 0x%08x, value = 0x%08x%08x", rec->extra[0], rec->extra[2], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x00E):
            ret = asprintf(&info_str, "func = 0x%08x, eax = 0x%08x, ebx = 0x%08x, ecx=0x%08x, edx = 0x%08x", rec->extra[0], rec->extra[1], rec->extra[2], rec->extra[3], rec->extra[4]);
            break;
        case (TRC_HVM_HANDLER | 0x00F):
            ret = asprintf(&info_str, "vector = 0x%02x", rec->extra[0]);
            break;
        //case (TRC_HVM_HANDLER | 0x010):
        //    ret = asprintf(&info_str, "");
        //    break;
        //case (TRC_HVM_HANDLER | 0x011):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_HVM_HANDLER | 0x012):
            ret = asprintf(&info_str, "func = 0x%08x", rec->extra[0]);
            break;
        case (TRC_HVM_HANDLER | 0x013):
            ret = asprintf(&info_str, "intpending = %d", rec->extra[0]);
            break;
        case (TRC_HVM_HANDLER | 0x014):
            ret = asprintf(&info_str, "is invlpga? = %d, virt = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x114):
            ret = asprintf(&info_str, "is invlpga? = %d, virt = 0x%08x%08x", rec->extra[0], rec->extra[2], rec->extra[1]);
            break;
        //case (TRC_HVM_HANDLER | 0x015):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_HVM_HANDLER | 0x016):
            ret = asprintf(&info_str, "port = 0x%04x, data = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x216):
            ret = asprintf(&info_str, "port = 0x%04x, data = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x017):
            ret = asprintf(&info_str, "port = 0x%08x, data = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_HANDLER | 0x217):
            ret = asprintf(&info_str, "port = 0x%08x, data = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        //case (TRC_HVM_HANDLER | 0x018):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_HVM_HANDLER | 0x019):
            ret = asprintf(&info_str, "value = 0x%08x", rec->extra[0]);
            break;
        case (TRC_HVM_HANDLER | 0x119):
            ret = asprintf(&info_str, "value = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_HVM_HANDLER | 0x01a):
            ret = asprintf(&info_str, "value = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_HVM_HANDLER | 0x020):
            ret = asprintf(&info_str, "value = 0x%08x", rec->extra[0]);
            break;
        case (TRC_HVM_HANDLER | 0x021):
            ret = asprintf(&info_str, "gpa = 0x%08x%08x mfn = 0x%08x%08x qual = 0x%04x p2mt = 0x%04x", rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2], rec->extra[4], rec->extra[5]);
            break;
        case (TRC_HVM_HANDLER | 0x023):
            ret = asprintf(&info_str, "vector = 0x%02x", rec->extra[0]);
            break;

        case (TRC_MEM | 0x001):
            ret = asprintf(&info_str, "domid = %d", rec->extra[0]);
            break;
        case (TRC_MEM | 0x002):
            ret = asprintf(&info_str, "domid = %d", rec->extra[0]);
            break;
        case (TRC_MEM | 0x003):
            ret = asprintf(&info_str, "domid = %d", rec->extra[0]);
            break;

        case (TRC_PV_ENTRY | 0x001):
            ret = asprintf(&info_str, "eip = 0x%08x, eax = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_PV_ENTRY | 0x101):
            ret = asprintf(&info_str, "rip = 0x%08x%08x, eax = 0x%08x", rec->extra[1], rec->extra[0], rec->extra[2]);
            break;
        case (TRC_PV_ENTRY | 0x003):
            ret = asprintf(&info_str, "eip = 0x%08x, trapnr:error = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_PV_ENTRY | 0x103):
            ret = asprintf(&info_str, "rip = 0x%08x%08x, trapnr:error = 0x%08x", rec->extra[1], rec->extra[0], rec->extra[2]);
            break;
        case (TRC_PV_ENTRY | 0x004):
            ret = asprintf(&info_str, "eip = 0x%08x, addr = 0x%08x, error = 0x%08x", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_PV_ENTRY | 0x104):
            ret = asprintf(&info_str, "rip = 0x%08x%08x, addr = 0x%08x%08x, error = 0x%08x", rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2], rec->extra[4]);
            break;
        case (TRC_PV_ENTRY | 0x005):
            ret = asprintf(&info_str, "eip = 0x%08x", rec->extra[0]);
            break;
        case (TRC_PV_ENTRY | 0x105):
            ret = asprintf(&info_str, "rip = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_PV_ENTRY | 0x006):
            ret = asprintf(&info_str, "eip = 0x%08x", rec->extra[0]);
            break;
        case (TRC_PV_ENTRY | 0x106):
            ret = asprintf(&info_str, "rip = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_PV_ENTRY | 0x007):
            ret = asprintf(&info_str, "eip = 0x%08x", rec->extra[0]);
            break;
        case (TRC_PV_ENTRY | 0x107):
            ret = asprintf(&info_str, "rip = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        //case (TRC_PV_ENTRY | 0x008):
        //    ret = asprintf(&info_str, "");
        //    break;
        //case (TRC_PV_ENTRY | 0x108):
        //    ret = asprintf(&info_str, "");
        //    break;
        case (TRC_PV_ENTRY | 0x009):
            ret = asprintf(&info_str, "eip = 0x%08x, addr = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_PV_ENTRY | 0x109):
            ret = asprintf(&info_str, "rip = 0x%08x%08x, addr = 0x%08x%08x", rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2]);
            break;
        case (TRC_PV_ENTRY | 0x00a):
            ret = asprintf(&info_str, "eip = 0x%08x, offset = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_PV_ENTRY | 0x10a):
            ret = asprintf(&info_str, "rip = 0x%08x%08x, offset = 0x%08x%08x", rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2]);
            break;
        case (TRC_PV_ENTRY | 0x00b):
            ret = asprintf(&info_str, "addr = 0x%08x, eip = 0x%08x, npte = 0x%08x%08x", rec->extra[2], rec->extra[3], rec->extra[1], rec->extra[0]);
            break;
        case (TRC_PV_ENTRY | 0x10b):
            ret = asprintf(&info_str, "addr = 0x%08x%08x, rip = 0x%08x%08x, npte = 0x%08x%08x", rec->extra[3], rec->extra[2], rec->extra[5], rec->extra[4], rec->extra[1], rec->extra[0]);
            break;
        case (TRC_PV_ENTRY | 0x00c):
            ret = asprintf(&info_str, "addr = 0x%08x, eip = 0x%08x, npte = 0x%08x%08x", rec->extra[2], rec->extra[3], rec->extra[1], rec->extra[0]);
            break;
        case (TRC_PV_ENTRY | 0x10c):
            ret = asprintf(&info_str, "addr = 0x%08x%08x, rip = 0x%08x%08x, npte = 0x%08x%08x", rec->extra[3], rec->extra[2], rec->extra[5], rec->extra[4], rec->extra[1], rec->extra[0]);
            break;
        case (TRC_PV_ENTRY | 0x00d):
            ret = asprintf(&info_str, "op = 0x%08x", rec->extra[0]);
            break;
        case (TRC_PV_SUBCALL | 0x00e):
            ret = asprintf(&info_str, "op = 0x%08x", rec->extra[0]);
            break;

        case (TRC_SHADOW | 0x001):
            ret = asprintf(&info_str, "gl1e = 0x%08x%08x, va = 0x%08x, flags = 0x%08x", rec->extra[1], rec->extra[0], rec->extra[2], rec->extra[4]);
            break;
        case (TRC_SHADOW | 0x101):
            ret = asprintf(&info_str, "gl1e = 0x%08x%08x, va = 0x%08x%08x, flags = 0x%08x", rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2], rec->extra[4]);
            break;
        case (TRC_SHADOW | 0x002):
            ret = asprintf(&info_str, "va = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x102):
            ret = asprintf(&info_str, "va = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x003):
            ret = asprintf(&info_str, "va = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x103):
            ret = asprintf(&info_str, "va = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x004):
            ret = asprintf(&info_str, "va = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x104):
            ret = asprintf(&info_str, "va = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x005):
            ret = asprintf(&info_str, "va = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x105):
            ret = asprintf(&info_str, "va = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x006):
            ret = asprintf(&info_str, "gl1e = 0x%08x, va = 0x%08x, flags = 0x%08x", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_SHADOW | 0x106):
            ret = asprintf(&info_str, "gl1e = 0x%08x%08x, va = 0x%08x%08x, flags = 0x%08x", rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2], rec->extra[2]);
            break;
        case (TRC_SHADOW | 0x007):
            ret = asprintf(&info_str, "va = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x107):
            ret = asprintf(&info_str, "va = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x008):
            ret = asprintf(&info_str, "gl1e = 0x%08x, write_val = 0x%08x, va = 0x%08x, flags = 0x%08x", rec->extra[0], rec->extra[1], rec->extra[2], rec->extra[3]);
            break;
        case (TRC_SHADOW | 0x108):
            ret = asprintf(&info_str, "gl1e = 0x%08x%08x, write_val = 0x%08x%08x, va = 0x%08x%08x, flags = 0x%08x", rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2], rec->extra[5], rec->extra[4], rec->extra[6]);
            break;
        case (TRC_SHADOW | 0x009):
            ret = asprintf(&info_str, "va = 0x%08x, gfn = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SHADOW | 0x109):
            ret = asprintf(&info_str, "va = 0x%08x%08x, gfn = 0x%08x%08x", rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2]);
            break;
        case (TRC_SHADOW | 0x00a):
            ret = asprintf(&info_str, "va = 0x%08x, gfn = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SHADOW | 0x10a):
            ret = asprintf(&info_str, "va = 0x%08x%08x, gfn = 0x%08x%08x", rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2]);
            break;
        case (TRC_SHADOW | 0x00b):
            ret = asprintf(&info_str, "va = 0x%08x, gfn = 0x%08x", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_SHADOW | 0x10b):
            ret = asprintf(&info_str, "va = 0x%08x%08x, gfn = 0x%08x%08x", rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2]);
            break;
        case (TRC_SHADOW | 0x00c):
            ret = asprintf(&info_str, "gfn = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x10c):
            ret = asprintf(&info_str, "gfn = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x00d):
            ret = asprintf(&info_str, "gfn = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x10d):
            ret = asprintf(&info_str, "gfn = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x00e):
            ret = asprintf(&info_str, "gfn = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x10e):
            ret = asprintf(&info_str, "gfn = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x00f):
            ret = asprintf(&info_str, "gfn = 0x%08x", rec->extra[0]);
            break;
        case (TRC_SHADOW | 0x10f):
            ret = asprintf(&info_str, "gfn = 0x%08x%08x", rec->extra[1], rec->extra[0]);
            break;

        case (TRC_HW_PM | 0x001):
            ret = asprintf(&info_str, "%dMHz -> %dMHz", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HW_PM | 0x002):
            ret = asprintf(&info_str, "C0 -> C%d, acpi_pm_tick = %d, expected = %dus, predicted = %dus", rec->extra[0], rec->extra[1], rec->extra[2], rec->extra[3]);
            break;
        case (TRC_HW_PM | 0x003):
            ret = asprintf(&info_str, "C%d -> C0, acpi_pm_tick = %d, irq = %d %d %d %d", rec->extra[0], rec->extra[1], rec->extra[2], rec->extra[3], rec->extra[4], rec->extra[5]);
            break;

        case (TRC_HW_IRQ | 0x001):
            ret = asprintf(&info_str, "irq = %d, vector 0x%x on CPU%d", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_HW_IRQ | 0x002):
            ret = asprintf(&info_str, "irq = %d, vector 0x%x on CPU%d", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_HW_IRQ | 0x003):
            ret = asprintf(&info_str, "irq = %d = vector 0x%x, CPU mask: 0x%08x", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_HW_IRQ | 0x004):
            ret = asprintf(&info_str, "irq = %d = vector 0x%x, CPU mask: 0x%08x", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_HW_IRQ | 0x005):
            ret = asprintf(&info_str, "irq = %d had vector 0x%x on CPU%d", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_HW_IRQ | 0x006):
            ret = asprintf(&info_str, "irq = %d = vector 0x%x, CPU mask: 0x%08x", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_HW_IRQ | 0x007):
            ret = asprintf(&info_str, "0x%x", rec->extra[0]);
            break;
        case (TRC_HW_IRQ | 0x008):
            ret = asprintf(&info_str, "irq = %d, began = %dus, ended = %dus", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;

        case (TRC_HVM_EMUL | 0x001):
            ret = asprintf(&info_str, "create [ tn = %d, irq = %d, delta = 0x%08x%08x, period = 0x%08x%08x ]", rec->extra[0], rec->extra[1], rec->extra[3], rec->extra[2], rec->extra[5], rec->extra[4]);
            break;
        case (TRC_HVM_EMUL | 0x002):
            ret = asprintf(&info_str, "create [ delta = 0x%016x, period = 0x%016x ]", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_EMUL | 0x003):
            ret = asprintf(&info_str, "create [ delta = 0x%016x , period = 0x%016x ]", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_EMUL | 0x004):
            ret = asprintf(&info_str, "create [ delta = 0x%08x%08x , period = 0x%08x%08x, irq = %d ]", rec->extra[1], rec->extra[0], rec->extra[3], rec->extra[2], rec->extra[4]);
            break;
        case (TRC_HVM_EMUL | 0x005):
            ret = asprintf(&info_str, "destroy [ tn = %d ]", rec->extra[0]);
            break;
        case (TRC_HVM_EMUL | 0x006):
            ret = asprintf(&info_str, "destroy  [ ]");
            break;
        case (TRC_HVM_EMUL | 0x007):
            ret = asprintf(&info_str, "destroy [ ]");
            break;
        case (TRC_HVM_EMUL | 0x008):
            ret = asprintf(&info_str, "destroy [ ]");
            break;
        case (TRC_HVM_EMUL | 0x009):
            ret = asprintf(&info_str, "callback [ ]");
            break;
        case (TRC_HVM_EMUL | 0x00a):
            ret = asprintf(&info_str, "callback [ ]");
            break;
        case (TRC_HVM_EMUL | 0x00b):
            ret = asprintf(&info_str, "int_output = %d, is_master = %d, irq = %d", rec->extra[0], rec->extra[1], rec->extra[2]);
            break;
        case (TRC_HVM_EMUL | 0x00c):
            ret = asprintf(&info_str, "vcpu_kick [ irq = %d ]", rec->extra[0]);
            break;
        case (TRC_HVM_EMUL | 0x00d):
            ret = asprintf(&info_str, "is_master = %d, irq = %d", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_EMUL | 0x00e):
            ret = asprintf(&info_str, "irq = %d", rec->extra[0]);
            break;
        case (TRC_HVM_EMUL | 0x00f):
            ret = asprintf(&info_str, "irq = %d", rec->extra[0]);
            break;
        case (TRC_HVM_EMUL | 0x010):
            ret = asprintf(&info_str, "accept_pic_intr = %d, int_output = %d", rec->extra[0], rec->extra[1]);
            break;
        case (TRC_HVM_EMUL | 0x011):
            ret = asprintf(&info_str, "i8259_target = %d, accept_pic_int = %d", rec->extra[0], rec->extra[1]);
            break;
    }

    if (ret <= 0)
        return NULL;

    return info_str;
}

/**
 * 
 */
static char *dump_entry(struct kshark_data_stream *stream,
                            const struct kshark_entry *entry)
{
    char *ev_task = get_task(stream, entry),
        *ev_name  = get_event_name(stream, entry),
        *ev_info  = get_info(stream, entry),
        *ev_dump;

    double ts = (double)entry->ts / 1e9;
    int ret = asprintf(&ev_dump, "%.6f - %s - %s [ %s ]", 
                                ts, ev_task, ev_name, ev_info);

    free(ev_task);
    free(ev_name);
    free(ev_info);

    if (ret <= 0)
        return NULL;

    return ev_dump;
}

/**
 *
 */
static int64_t tsc_to_ns(uint64_t tsc)
{
    // TODO Check absolute time conversion
    return ((tsc - I.first_tsc)) / I.cpu_qhz;
}

/**
 * Loads the content of the XenTrace binary file.
 */
static ssize_t load_entries(struct kshark_data_stream *stream,
                                struct kshark_context *kshark_ctx,
                                struct kshark_entry ***data_rows)
{
    int n_events = xtp_events_count(I.parser),
             pos = 0;
    struct kshark_entry **rows = calloc(n_events, sizeof(struct kshark_entry*));

    xt_event *event;
    while ( (event = xtp_next_event(I.parser)) ) {
        // Utility vars
        xt_header *hdr = &event->hdr;
        xt_record *rec = &event->rec;

        // Initialize KS row
        rows[pos] = calloc(1, sizeof(struct kshark_entry));

        // Populate members of the KS row
        rows[pos]->stream_id = stream->stream_id;
        rows[pos]->visible = 0xff;
        rows[pos]->offset = pos;

        rows[pos]->event_id = rec->id; // FIXME  int16_t < uint32_t:28  ¯\_(ツ)_/¯
        rows[pos]->cpu = hdr->cpu;
        rows[pos]->ts  = tsc_to_ns(rec->tsc);

        if (hdr->dom != XEN_DOM_IDLE) {
            int task_id = ((hdr->dom << 16) | hdr->vcpu) + 1;
            kshark_hash_id_add(stream->tasks, task_id);
            rows[pos]->pid = task_id;
        } // else 0

        // Go next
        ++pos;
    }

    *data_rows = rows;
    return n_events;
}

/**
 *
 */
static void read_env_vars()
{
    // Read trace CPU Hz (or set default val)
    char* env_cpu_hz = secure_getenv(ENV_XEN_CPUHZ);
    I.cpu_hz = env_cpu_hz ? strtol(env_cpu_hz, NULL, 10) : DEFAULT_CPU_HZ;
    I.cpu_qhz = QHZ_FROM_HZ(I.cpu_hz);

    
    // Save the tsc of the first event to
    // perform the calc of the relative ts.
    char* env_abs_ts = secure_getenv(ENV_XEN_ABSTS);
    char abs_ts = env_abs_ts && ((*env_abs_ts == '1') ||
                                    (*env_abs_ts == 'y') ||
                                        (*env_abs_ts == 'Y'));
    I.first_tsc = abs_ts ? 0 : ((xtp_get_event(I.parser, 0))->rec).tsc;

    // TODO Others... ?
}

/**
 * Initializes all methods used to process XENTRACE data.
 */
static void init_methods(struct kshark_generic_stream_interface *interface)
{
    interface->get_event_name = get_event_name;
    interface->get_task = get_task;
    interface->get_pid  = get_pid;
    interface->get_info = get_info;

    interface->load_entries = load_entries;
    interface->dump_entry   = dump_entry;
}

/**
 * Checks if the file contains XEN tracing data.
 */
bool KSHARK_INPUT_CHECK(const char *file, char **format)
{
    FILE *fp = fopen(file, "rb");
    if (!fp)
        return false;

    uint32_t event_id;
    int fret = fread(&event_id, sizeof(event_id), 1, fp) == 1;
    fclose(fp);

    // TRC_TRACE_CPU_CHANGE should be the first record
    return fret && ((event_id & 0x0fffffff) == TRC_TRACE_CPU_CHANGE);
}

/**
 * Returns format name.
 */
const char *KSHARK_INPUT_FORMAT()
{
    return format_name;
}

/**
 * Loads plugin.
 */
int KSHARK_INPUT_INITIALIZER(struct kshark_data_stream *stream)
{
    struct kshark_generic_stream_interface *interface;

    stream->interface = interface = calloc(1, sizeof(struct kshark_generic_stream_interface));
    if (!interface)
        return -ENOMEM;

    interface->type = KS_GENERIC_DATA_INTERFACE;

    // Initialize XenTrace Parser
    I.parser = xtp_init(stream->file);
    unsigned n_events = xtp_execute(I.parser);
    if (!(I.parser && n_events)) {
        free(interface);
        return -ENOMEM;
    }

    // ...
    stream->n_events = n_events;
    stream->n_cpus   = xtp_cpus_count(I.parser);
    stream->idle_pid = 0;

    // Read environment vars
    read_env_vars();

    // Setup methods references
    init_methods(interface);

    return 0;
}

/**
 * Unloads plugin.
 */
void KSHARK_INPUT_DEINITIALIZER(struct kshark_data_stream *stream)
{
    xtp_free(I.parser);
}