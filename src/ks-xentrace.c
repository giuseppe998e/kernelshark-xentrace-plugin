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

    xt_record *rec = &event->rec;
    char *event_str;
    int ret = 0;

    switch (rec->id) {
        case (TRC_GEN | 0x001):
            ret = asprintf(&event_str, "lost_records");
            break;
        case (TRC_GEN | 0x002):
            ret = asprintf(&event_str, "wrap_buffer");
            break;
        //case (TRC_GEN | 0x003):
        //    ret = asprintf(&event_str, "cpu_change");
        //    break;
        case (TRC_GEN | 0x004):
            ret = asprintf(&event_str, "trace_irq");
            break;

        case (TRC_SCHED_MIN | 0x002):
            ret = asprintf(&event_str, "continue_running");
            break;
        case (TRC_SCHED_MIN | 0x011):
            ret = asprintf(&event_str, "running_to_runnable");
            break;
        case (TRC_SCHED_MIN | 0x021):
            ret = asprintf(&event_str, "running_to_blocked");
            break;
        case (TRC_SCHED_MIN | 0x031):
            ret = asprintf(&event_str, "running_to_offline");
            break;
        case (TRC_SCHED_MIN | 0x101):
            ret = asprintf(&event_str, "runnable_to_running");
            break;
        case (TRC_SCHED_MIN | 0x121):
            ret = asprintf(&event_str, "runnable_to_blocked");
            break;
        case (TRC_SCHED_MIN | 0x131):
            ret = asprintf(&event_str, "runnable_to_offline");
            break;
        case (TRC_SCHED_MIN | 0x201):
            ret = asprintf(&event_str, "blocked_to_running");
            break;
        case (TRC_SCHED_MIN | 0x211):
            ret = asprintf(&event_str, "blocked_to_runnable");
            break;
        case (TRC_SCHED_MIN | 0x231):
            ret = asprintf(&event_str, "blocked_to_offline");
            break;
        case (TRC_SCHED_MIN | 0x301):
            ret = asprintf(&event_str, "offline_to_running");
            break;
        case (TRC_SCHED_MIN | 0x311):
            ret = asprintf(&event_str, "offline_to_runnable");
            break;
        case (TRC_SCHED_MIN | 0x321):
            ret = asprintf(&event_str, "offline_to_blocked");
            break;

        case (TRC_SCHED_VERBOSE | 0x001):
            ret = asprintf(&event_str, "sched_add_domain");
            break;
        case (TRC_SCHED_VERBOSE | 0x002):
            ret = asprintf(&event_str, "sched_rem_domain");
            break;
        case (TRC_SCHED_VERBOSE | 0x003):
            ret = asprintf(&event_str, "domain_sleep");
            break;
        case (TRC_SCHED_VERBOSE | 0x004):
            ret = asprintf(&event_str, "domain_wake");
            break;
        case (TRC_SCHED_VERBOSE | 0x005):
            ret = asprintf(&event_str, "do_yield");
            break;
        case (TRC_SCHED_VERBOSE | 0x006):
            ret = asprintf(&event_str, "do_block");
            break;
        case (TRC_SCHED_VERBOSE | 0x007):
            ret = asprintf(&event_str, "domain_shutdown");
            break;
        case (TRC_SCHED_VERBOSE | 0x008):
            ret = asprintf(&event_str, "sched_ctl");
            break;
        case (TRC_SCHED_VERBOSE | 0x009):
            ret = asprintf(&event_str, "sched_adjdom");
            break;
        case (TRC_SCHED_VERBOSE | 0x00a):
            ret = asprintf(&event_str, "__enter_scheduler");
            break;
        case (TRC_SCHED_VERBOSE | 0x00b):
            ret = asprintf(&event_str, "s_timer_fn");
            break;
        case (TRC_SCHED_VERBOSE | 0x00c):
            ret = asprintf(&event_str, "t_timer_fn");
            break;
        case (TRC_SCHED_VERBOSE | 0x00d):
            ret = asprintf(&event_str, "dom_timer_fn");
            break;
        case (TRC_SCHED_VERBOSE | 0x00e):
            ret = asprintf(&event_str, "switch_infprev");
            break;
        case (TRC_SCHED_VERBOSE | 0x00f):
            ret = asprintf(&event_str, "switch_infnext");
            break;
        case (TRC_SCHED_VERBOSE | 0x010):
            ret = asprintf(&event_str, "domain_shutdown_code");
            break;
        case (TRC_SCHED_VERBOSE | 0x011):
            ret = asprintf(&event_str, "switch_infcont");
            break;

        case (TRC_SCHED_CLASS | 0x001):
            ret = asprintf(&event_str, "csched:sched_tasklet");
            break;
        case (TRC_SCHED_CLASS | 0x002):
            ret = asprintf(&event_str, "csched:account_start");
            break;
        case (TRC_SCHED_CLASS | 0x003):
            ret = asprintf(&event_str, "csched:account_stop");
            break;
        case (TRC_SCHED_CLASS | 0x004):
            ret = asprintf(&event_str, "csched:stolen_vcpu");
            break;
        case (TRC_SCHED_CLASS | 0x005):
            ret = asprintf(&event_str, "csched:picked_cpu");
            break;
        case (TRC_SCHED_CLASS | 0x006):
            ret = asprintf(&event_str, "csched:tickle");
            break;
        case (TRC_SCHED_CLASS | 0x007):
            ret = asprintf(&event_str, "csched:boost");
            break;
        case (TRC_SCHED_CLASS | 0x008):
            ret = asprintf(&event_str, "csched:unboost");
            break;
        case (TRC_SCHED_CLASS | 0x009):
            ret = asprintf(&event_str, "csched:schedule");
            break;
        case (TRC_SCHED_CLASS | 0x00A):
            ret = asprintf(&event_str, "csched:ratelimit");
            break;
        case (TRC_SCHED_CLASS | 0x00B):
            ret = asprintf(&event_str, "csched:steal_check");
            break;

        case (TRC_SCHED_CLASS | 0x201):
            ret = asprintf(&event_str, "csched2:tick");
            break;
        case (TRC_SCHED_CLASS | 0x202):
            ret = asprintf(&event_str, "csched2:runq_pos");
            break;
        case (TRC_SCHED_CLASS | 0x203):
            ret = asprintf(&event_str, "csched2:credit_burn");
            break;
        case (TRC_SCHED_CLASS | 0x204):
            ret = asprintf(&event_str, "csched2:credit_add");
            break;
        case (TRC_SCHED_CLASS | 0x205):
            ret = asprintf(&event_str, "csched2:tickle_check"); // FIXME format file R#54
            break;
        case (TRC_SCHED_CLASS | 0x206):
            ret = asprintf(&event_str, "csched2:tickle");
            break;
        case (TRC_SCHED_CLASS | 0x207):
            ret = asprintf(&event_str, "csched2:credit_reset");
            break;
        case (TRC_SCHED_CLASS | 0x208):
            ret = asprintf(&event_str, "csched2:sched_tasklet");
            break;
        case (TRC_SCHED_CLASS | 0x209):
            ret = asprintf(&event_str, "csched2:update_load");
            break;
        case (TRC_SCHED_CLASS | 0x20a):
            ret = asprintf(&event_str, "csched2:runq_assign");
            break;
        case (TRC_SCHED_CLASS | 0x20b):
            ret = asprintf(&event_str, "csched2:updt_vcpu_load");
            break;
        case (TRC_SCHED_CLASS | 0x20c):
            ret = asprintf(&event_str, "csched2:updt_runq_load");
            break;
        case (TRC_SCHED_CLASS | 0x20d):
            ret = asprintf(&event_str, "csched2:tickle_new");
            break;
        case (TRC_SCHED_CLASS | 0x20e):
            ret = asprintf(&event_str, "csched2:runq_max_weight");
            break;
        case (TRC_SCHED_CLASS | 0x20f):
            ret = asprintf(&event_str, "csched2:migrrate");
            break;
        case (TRC_SCHED_CLASS | 0x210):
            ret = asprintf(&event_str, "csched2:load_check");
            break;
        case (TRC_SCHED_CLASS | 0x211):
            ret = asprintf(&event_str, "csched2:load_balance");
            break;
        case (TRC_SCHED_CLASS | 0x212):
            ret = asprintf(&event_str, "csched2:pick_cpu");
            break;
        case (TRC_SCHED_CLASS | 0x213):
            ret = asprintf(&event_str, "csched2:runq_candidate");
            break;
        case (TRC_SCHED_CLASS | 0x214):
            ret = asprintf(&event_str, "csched2:schedule");
            break;
        case (TRC_SCHED_CLASS | 0x215):
            ret = asprintf(&event_str, "csched2:ratelimit");
            break;
        case (TRC_SCHED_CLASS | 0x216):
            ret = asprintf(&event_str, "csched2:runq_cand_chk");
            break;

        case (TRC_SCHED_CLASS | 0x801):
            ret = asprintf(&event_str, "rtds:tickle");
            break;
        case (TRC_SCHED_CLASS | 0x802):
            ret = asprintf(&event_str, "rtds:runq_pick");
            break;
        case (TRC_SCHED_CLASS | 0x803):
            ret = asprintf(&event_str, "rtds:burn_budget");
            break;
        case (TRC_SCHED_CLASS | 0x804):
            ret = asprintf(&event_str, "rtds:repl_budget");
            break;
        case (TRC_SCHED_CLASS | 0x805):
            ret = asprintf(&event_str, "rtds:sched_tasklet");
            break;
        case (TRC_SCHED_CLASS | 0x806):
            ret = asprintf(&event_str, "rtds:schedule");
            break;

        case (TRC_SCHED_CLASS | 0xA01):
            ret = asprintf(&event_str, "null:pick_cpu");
            break;
        case (TRC_SCHED_CLASS | 0xA02):
            ret = asprintf(&event_str, "null:assign");
            break;
        case (TRC_SCHED_CLASS | 0xA03):
            ret = asprintf(&event_str, "null:deassign");
            break;
        case (TRC_SCHED_CLASS | 0xA04):
            ret = asprintf(&event_str, "null:migrate");
            break;
        case (TRC_SCHED_CLASS | 0xA05):
            ret = asprintf(&event_str, "null:schedule");
            break;
        case (TRC_SCHED_CLASS | 0xA06):
            ret = asprintf(&event_str, "null:sched_tasklet");
            break;

        case (TRC_DOM0_DOMOPS | 0x001):
            ret = asprintf(&event_str, "domain_create");
            break;
        case (TRC_DOM0_DOMOPS | 0x002):
            ret = asprintf(&event_str, "domain_destroy");
            break;

        case (TRC_HVM_ENTRYEXIT | 0x001):
            ret = asprintf(&event_str, "VMENTRY");
            break;
        case (TRC_HVM_ENTRYEXIT | 0x002):
            ret = asprintf(&event_str, "VMEXIT");
            break;
        case (TRC_HVM_ENTRYEXIT | 0x102):
            ret = asprintf(&event_str, "VMEXIT");
            break;
        case (TRC_HVM_ENTRYEXIT | 0x401):
            ret = asprintf(&event_str, "nVMENTRY");
            break;
        case (TRC_HVM_ENTRYEXIT | 0x402):
            ret = asprintf(&event_str, "nVMEXIT");
            break;
        case (TRC_HVM_ENTRYEXIT | 0x502):
            ret = asprintf(&event_str, "nVMEXIT");
            break;
        case (TRC_HVM_HANDLER | 0x001):
            ret = asprintf(&event_str, "PF_XEN");
            break;
        case (TRC_HVM_HANDLER | 0x101):
            ret = asprintf(&event_str, "PF_XEN");
            break;
        case (TRC_HVM_HANDLER | 0x002):
            ret = asprintf(&event_str, "PF_INJECT");
            break;
        case (TRC_HVM_HANDLER | 0x102):
            ret = asprintf(&event_str, "PF_INJECT");
            break;
        case (TRC_HVM_HANDLER | 0x003):
            ret = asprintf(&event_str, "INJ_EXC");
            break;
        case (TRC_HVM_HANDLER | 0x004):
            ret = asprintf(&event_str, "INJ_VIRQ");
            break;
        case (TRC_HVM_HANDLER | 0x005):
            ret = asprintf(&event_str, "REINJ_VIRQ");
            break;
        case (TRC_HVM_HANDLER | 0x006):
            ret = asprintf(&event_str, "IO_READ");
            break;
        case (TRC_HVM_HANDLER | 0x007):
            ret = asprintf(&event_str, "IO_WRITE");
            break;
        case (TRC_HVM_HANDLER | 0x008):
            ret = asprintf(&event_str, "CR_READ");
            break;
        case (TRC_HVM_HANDLER | 0x108):
            ret = asprintf(&event_str, "CR_READ");
            break;
        case (TRC_HVM_HANDLER | 0x009):
            ret = asprintf(&event_str, "CR_WRITE");
            break;
        case (TRC_HVM_HANDLER | 0x109):
            ret = asprintf(&event_str, "CR_WRITE");
            break;
        case (TRC_HVM_HANDLER | 0x00A):
            ret = asprintf(&event_str, "DR_READ");
            break;
        case (TRC_HVM_HANDLER | 0x00B):
            ret = asprintf(&event_str, "DR_WRITE");
            break;
        case (TRC_HVM_HANDLER | 0x00C):
            ret = asprintf(&event_str, "MSR_READ");
            break;
        case (TRC_HVM_HANDLER | 0x00D):
            ret = asprintf(&event_str, "MSR_WRITE");
            break;
        case (TRC_HVM_HANDLER | 0x00E):
            ret = asprintf(&event_str, "CPUID");
            break;
        case (TRC_HVM_HANDLER | 0x00F):
            ret = asprintf(&event_str, "INTR");
            break;
        case (TRC_HVM_HANDLER | 0x010):
            ret = asprintf(&event_str, "NMI");
            break;
        case (TRC_HVM_HANDLER | 0x011):
            ret = asprintf(&event_str, "SMI");
            break;
        case (TRC_HVM_HANDLER | 0x012):
            ret = asprintf(&event_str, "VMMCALL");
            break;
        case (TRC_HVM_HANDLER | 0x013):
            ret = asprintf(&event_str, "HLT");
            break;
        case (TRC_HVM_HANDLER | 0x014):
            ret = asprintf(&event_str, "INVLPG");
            break;
        case (TRC_HVM_HANDLER | 0x114):
            ret = asprintf(&event_str, "INVLPG");
            break;
        case (TRC_HVM_HANDLER | 0x015):
            ret = asprintf(&event_str, "MCE");
            break;
        case (TRC_HVM_HANDLER | 0x016):
            ret = asprintf(&event_str, "IOPORT_READ");
            break;
        case (TRC_HVM_HANDLER | 0x216):
            ret = asprintf(&event_str, "IOPORT_WRITE");
            break;
        case (TRC_HVM_HANDLER | 0x017):
            ret = asprintf(&event_str, "MMIO_READ");
            break;
        case (TRC_HVM_HANDLER | 0x217):
            ret = asprintf(&event_str, "MMIO_WRITE");
            break;
        case (TRC_HVM_HANDLER | 0x018):
            ret = asprintf(&event_str, "CLTS");
            break;
        case (TRC_HVM_HANDLER | 0x019):
            ret = asprintf(&event_str, "LMSW");
            break;
        case (TRC_HVM_HANDLER | 0x119):
            ret = asprintf(&event_str, "LMSW");
            break;
        case (TRC_HVM_HANDLER | 0x01a):
            ret = asprintf(&event_str, "RDTSC");
            break;
        case (TRC_HVM_HANDLER | 0x020):
            ret = asprintf(&event_str, "INTR_WINDOW");
            break;
        case (TRC_HVM_HANDLER | 0x021):
            ret = asprintf(&event_str, "NPF");
            break;
        case (TRC_HVM_HANDLER | 0x023):
            ret = asprintf(&event_str, "TRAP");
            break;

        case (TRC_MEM | 0x001):
            ret = asprintf(&event_str, "page_grant_map");
            break;
        case (TRC_MEM | 0x002):
            ret = asprintf(&event_str, "page_grant_unmap");
            break;
        case (TRC_MEM | 0x003):
            ret = asprintf(&event_str, "page_grant_transfer");
            break;

        case (TRC_PV_ENTRY | 0x001):
            ret = asprintf(&event_str, "hypercall");
            break;
        case (TRC_PV_ENTRY | 0x101):
            ret = asprintf(&event_str, "hypercall");
            break;
        case (TRC_PV_ENTRY | 0x003):
            ret = asprintf(&event_str, "trap");
            break;
        case (TRC_PV_ENTRY | 0x103):
            ret = asprintf(&event_str, "trap");
            break;
        case (TRC_PV_ENTRY | 0x004):
            ret = asprintf(&event_str, "page_fault");
            break;
        case (TRC_PV_ENTRY | 0x104):
            ret = asprintf(&event_str, "page_fault");
            break;
        case (TRC_PV_ENTRY | 0x005):
            ret = asprintf(&event_str, "forced_invalid_op");
            break;
        case (TRC_PV_ENTRY | 0x105):
            ret = asprintf(&event_str, "forced_invalid_op");
            break;
        case (TRC_PV_ENTRY | 0x006):
            ret = asprintf(&event_str, "emulate_privop");
            break;
        case (TRC_PV_ENTRY | 0x106):
            ret = asprintf(&event_str, "emulate_privop");
            break;
        case (TRC_PV_ENTRY | 0x007):
            ret = asprintf(&event_str, "emulate_4G");
            break;
        case (TRC_PV_ENTRY | 0x107):
            ret = asprintf(&event_str, "emulate_4G");
            break;
        case (TRC_PV_ENTRY | 0x008):
            ret = asprintf(&event_str, "math_state_restore");
            break;
        case (TRC_PV_ENTRY | 0x108):
            ret = asprintf(&event_str, "math_state_restore");
            break;
        case (TRC_PV_ENTRY | 0x009):
            ret = asprintf(&event_str, "paging_fixup");
            break;
        case (TRC_PV_ENTRY | 0x109):
            ret = asprintf(&event_str, "paging_fixup");
            break;
        case (TRC_PV_ENTRY | 0x00a):
            ret = asprintf(&event_str, "gdt_ldt_mapping_fault");
            break;
        case (TRC_PV_ENTRY | 0x10a):
            ret = asprintf(&event_str, "gdt_ldt_mapping_fault");
            break;
        case (TRC_PV_ENTRY | 0x00b):
            ret = asprintf(&event_str, "ptwr_emulation");
            break;
        case (TRC_PV_ENTRY | 0x10b):
            ret = asprintf(&event_str, "ptwr_emulation");
            break;
        case (TRC_PV_ENTRY | 0x00c):
            ret = asprintf(&event_str, "ptwr_emulation_pae");
            break;
        case (TRC_PV_ENTRY | 0x10c):
            ret = asprintf(&event_str, "ptwr_emulation_pae");
            break;
        case (TRC_PV_ENTRY | 0x00d):
            ret = asprintf(&event_str, "hypercall");
            break;
        case (TRC_PV_SUBCALL | 0x00e):
            ret = asprintf(&event_str, "hypercall");
            break;

        case (TRC_SHADOW | 0x001):
            ret = asprintf(&event_str, "shadow_not_shadow");
            break;
        case (TRC_SHADOW | 0x101):
            ret = asprintf(&event_str, "shadow_not_shadow");
            break;
        case (TRC_SHADOW | 0x002):
            ret = asprintf(&event_str, "shadow_fast_propagate");
            break;
        case (TRC_SHADOW | 0x102):
            ret = asprintf(&event_str, "shadow_fast_propagate");
            break;
        case (TRC_SHADOW | 0x003):
            ret = asprintf(&event_str, "shadow_fast_mmio");
            break;
        case (TRC_SHADOW | 0x103):
            ret = asprintf(&event_str, "shadow_fast_mmio");
            break;
        case (TRC_SHADOW | 0x004):
            ret = asprintf(&event_str, "shadow_false_fast_path");
            break;
        case (TRC_SHADOW | 0x104):
            ret = asprintf(&event_str, "shadow_false_fast_path");
            break;
        case (TRC_SHADOW | 0x005):
            ret = asprintf(&event_str, "shadow_mmio");
            break;
        case (TRC_SHADOW | 0x105):
            ret = asprintf(&event_str, "shadow_mmio");
            break;
        case (TRC_SHADOW | 0x006):
            ret = asprintf(&event_str, "shadow_fixup");
            break;
        case (TRC_SHADOW | 0x106):
            ret = asprintf(&event_str, "shadow_fixup");
            break;
        case (TRC_SHADOW | 0x007):
            ret = asprintf(&event_str, "shadow_domf_dying");
            break;
        case (TRC_SHADOW | 0x107):
            ret = asprintf(&event_str, "shadow_domf_dying");
            break;
        case (TRC_SHADOW | 0x008):
            ret = asprintf(&event_str, "shadow_emulate");
            break;
        case (TRC_SHADOW | 0x108):
            ret = asprintf(&event_str, "shadow_emulate");
            break;
        case (TRC_SHADOW | 0x009):
            ret = asprintf(&event_str, "shadow_emulate_unshadow_user");
            break;
        case (TRC_SHADOW | 0x109):
            ret = asprintf(&event_str, "shadow_emulate_unshadow_user");
            break;
        case (TRC_SHADOW | 0x00a):
            ret = asprintf(&event_str, "shadow_emulate_unshadow_evtinj");
            break;
        case (TRC_SHADOW | 0x10a):
            ret = asprintf(&event_str, "shadow_emulate_unshadow_evtinj");
            break;
        case (TRC_SHADOW | 0x00b):
            ret = asprintf(&event_str, "shadow_emulate_unshadow_unhandled");
            break;
        case (TRC_SHADOW | 0x10b):
            ret = asprintf(&event_str, "shadow_emulate_unshadow_unhandled");
            break;
        case (TRC_SHADOW | 0x00c):
            ret = asprintf(&event_str, "shadow_emulate_wrmap_bf");
            break;
        case (TRC_SHADOW | 0x10c):
            ret = asprintf(&event_str, "shadow_emulate_wrmap_bf");
            break;
        case (TRC_SHADOW | 0x00d):
            ret = asprintf(&event_str, "shadow_emulate_prealloc_unpin");
            break;
        case (TRC_SHADOW | 0x10d):
            ret = asprintf(&event_str, "shadow_emulate_prealloc_unpin");
            break;
        case (TRC_SHADOW | 0x00e):
            ret = asprintf(&event_str, "shadow_emulate_resync_full");
            break;
        case (TRC_SHADOW | 0x10e):
            ret = asprintf(&event_str, "shadow_emulate_resync_full");
            break;
        case (TRC_SHADOW | 0x00f):
            ret = asprintf(&event_str, "shadow_emulate_resync_only");
            break;
        case (TRC_SHADOW | 0x10f):
            ret = asprintf(&event_str, "shadow_emulate_resync_only");
            break;

        case (TRC_HW_PM | 0x001):
            ret = asprintf(&event_str, "cpu_freq_change");
            break;
        case (TRC_HW_PM | 0x002):
            ret = asprintf(&event_str, "cpu_idle_entry");
            break;
        case (TRC_HW_PM | 0x003):
            ret = asprintf(&event_str, "cpu_idle_exit");
            break;

        case (TRC_HW_IRQ | 0x001):
            ret = asprintf(&event_str, "cleanup_move_delayed");
            break;
        case (TRC_HW_IRQ | 0x002):
            ret = asprintf(&event_str, "cleanup_move");
            break;
        case (TRC_HW_IRQ | 0x003):
            ret = asprintf(&event_str, "bind_vector");
            break;
        case (TRC_HW_IRQ | 0x004):
            ret = asprintf(&event_str, "clear_vector");
            break;
        case (TRC_HW_IRQ | 0x005):
            ret = asprintf(&event_str, "move_vector");
            break;
        case (TRC_HW_IRQ | 0x006):
            ret = asprintf(&event_str, "assign_vector");
            break;
        case (TRC_HW_IRQ | 0x007):
            ret = asprintf(&event_str, "bogus_vector");
            break;
        case (TRC_HW_IRQ | 0x008):
            ret = asprintf(&event_str, "do_irq");
            break;

        case (TRC_HVM_EMUL | 0x001):
            ret = asprintf(&event_str, "hpet");
            break;
        case (TRC_HVM_EMUL | 0x002):
            ret = asprintf(&event_str, "pit");
            break;
        case (TRC_HVM_EMUL | 0x003):
            ret = asprintf(&event_str, "rtc");
            break;
        case (TRC_HVM_EMUL | 0x004):
            ret = asprintf(&event_str, "vlapic");
            break;
        case (TRC_HVM_EMUL | 0x005):
            ret = asprintf(&event_str, "hpet");
            break;
        case (TRC_HVM_EMUL | 0x006):
            ret = asprintf(&event_str, "pit");
            break;
        case (TRC_HVM_EMUL | 0x007):
            ret = asprintf(&event_str, "rtc");
            break;
        case (TRC_HVM_EMUL | 0x008):
            ret = asprintf(&event_str, "vlapic");
            break;
        case (TRC_HVM_EMUL | 0x009):
            ret = asprintf(&event_str, "pit");
            break;
        case (TRC_HVM_EMUL | 0x00a):
            ret = asprintf(&event_str, "vlapic");
            break;
        case (TRC_HVM_EMUL | 0x00b):
            ret = asprintf(&event_str, "vpic_update_int_output");
            break;
        case (TRC_HVM_EMUL | 0x00c):
            ret = asprintf(&event_str, "vpic");
            break;
        case (TRC_HVM_EMUL | 0x00d):
            ret = asprintf(&event_str, "__vpic_intack");
            break;
        case (TRC_HVM_EMUL | 0x00e):
            ret = asprintf(&event_str, "vpic_irq_positive_edge");
            break;
        case (TRC_HVM_EMUL | 0x00f):
            ret = asprintf(&event_str, "vpic_irq_negative_edge");
            break;
        case (TRC_HVM_EMUL | 0x010):
            ret = asprintf(&event_str, "vpic_ack_pending_irq");
            break;
        case (TRC_HVM_EMUL | 0x011):
            ret = asprintf(&event_str, "vlapic_accept_pic_intr");
            break;
        /* Default case */
        default:
            ret = asprintf(&event_str, "unknown (0x%08x)", rec->id);
            break;
    }

    if (ret <= 0)
        return NULL;

    return event_str;
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
    char *ev_task  = get_task(stream, entry),
        *ev_name = get_event_name(stream, entry),
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
    return ((tsc - I.first_tsc) << 10) / I.cpu_qhz;
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