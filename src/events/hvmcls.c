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

static int hvm_emul_evname(const uint32_t event_sub, char *result_str)
{
    switch (event_sub) {
        case 0x001:
        case 0x005:
            return sprintf(result_str, "hpet");
        case 0x002:
        case 0x006:
        case 0x009:
            return sprintf(result_str, "pit");
        case 0x003:
        case 0x007:
            return sprintf(result_str, "rtc");
        case 0x004:
        case 0x008:
        case 0x00a:
            return sprintf(result_str, "vlapic");
        case 0x00b:
            return sprintf(result_str, "vpic_update_int_output");
        case 0x00c:
            return sprintf(result_str, "vpic");
        case 0x00d:
            return sprintf(result_str, "__vpic_intack");
        case 0x00e:
            return sprintf(result_str, "vpic_irq_positive_edge");
        case 0x00f:
            return sprintf(result_str, "vpic_irq_negative_edge");
        case 0x010:
            return sprintf(result_str, "vpic_ack_pending_irq");
        case 0x011:
            return sprintf(result_str, "vlapic_accept_pic_intr");
        default:
            return 0;
    }
}

static int hvm_entryexit_evname(const uint32_t event_sub, char *result_str)
{
    switch (event_sub) {
        case 0x001:
            return sprintf(result_str, "VMENTRY");
        case 0x002:
        case 0x102:
            return sprintf(result_str, "VMEXIT");
        case 0x401:
            return sprintf(result_str, "nVMENTRY");
        case 0x402:
        case 0x502:
            return sprintf(result_str, "nVMEXIT");
        default:
            return 0;
    }
}

static int hvm_handler_evname(const uint32_t event_sub, char *result_str)
{
    switch (event_sub) {
        case 0x101:
            return sprintf(result_str, "PF_XEN");
        case 0x002:
        case 0x102:
            return sprintf(result_str, "PF_INJECT");
        case 0x003:
            return sprintf(result_str, "INJ_EXC");
        case 0x004:
            return sprintf(result_str, "INJ_VIRQ");
        case 0x005:
            return sprintf(result_str, "REINJ_VIRQ");
        case 0x006:
            return sprintf(result_str, "IO_READ");
        case 0x007:
            return sprintf(result_str, "IO_WRITE");
        case 0x008:
        case 0x108:
            return sprintf(result_str, "CR_READ");
        case 0x009:
        case 0x109:
            return sprintf(result_str, "CR_WRITE");
        case 0x00A:
            return sprintf(result_str, "DR_READ");
        case 0x00B:
            return sprintf(result_str, "DR_WRITE");
        case 0x00C:
            return sprintf(result_str, "MSR_READ");
        case 0x00D:
            return sprintf(result_str, "MSR_WRITE");
        case 0x00E:
            return sprintf(result_str, "CPUID");
        case 0x00F:
            return sprintf(result_str, "INTR");
        case 0x010:
            return sprintf(result_str, "NMI");
        case 0x011:
            return sprintf(result_str, "SMI");
        case 0x012:
            return sprintf(result_str, "VMMCALL");
        case 0x013:
            return sprintf(result_str, "HLT");
        case 0x014:
        case 0x114:
            return sprintf(result_str, "INVLPG");
        case 0x015:
            return sprintf(result_str, "MCE");
        case 0x016:
            return sprintf(result_str, "IOPORT_READ");
        case 0x216:
            return sprintf(result_str, "IOPORT_WRITE");
        case 0x017:
            return sprintf(result_str, "MMIO_READ");
        case 0x217:
            return sprintf(result_str, "MMIO_WRITE");
        case 0x018:
            return sprintf(result_str, "CLTS");
        case 0x019:
        case 0x119:
            return sprintf(result_str, "LMSW");
        case 0x01a:
            return sprintf(result_str, "RDTSC");
        case 0x020:
            return sprintf(result_str, "INTR_WINDOW");
        case 0x021:
            return sprintf(result_str, "NPF");
        case 0x023:
            return sprintf(result_str, "TRAP");
        default:
            return 0;
    }
}

int get_hvmcls_evname(const uint32_t event_id, char *result_str)
{
    int event_sub = event_id & 0x00000fff;
    switch (GET_EVENT_SUBCLS(event_id)) {
        case GET_EVENT_SUBCLS(TRC_HVM_EMUL):
            return hvm_emul_evname(event_sub, result_str);
        case GET_EVENT_SUBCLS(TRC_HVM_ENTRYEXIT):
            return hvm_entryexit_evname(event_sub, result_str);
        case GET_EVENT_SUBCLS(TRC_HVM_HANDLER):
            return hvm_handler_evname(event_sub, result_str);
        default:
            return 0;
    }
}

//
// EVENT INFO
//

static int hvm_emul_evinfo(const uint32_t event_sub,
                    const uint32_t *event_extra, char *result_str)
{
    switch (event_sub) {
        case 0x001:
            return sprintf(result_str, "create [ tn = %d, irq = %d, delta = 0x%08x%08x, period = 0x%08x%08x ]",
                                event_extra[0], event_extra[1], event_extra[3],
                                event_extra[2], event_extra[5], event_extra[4]);
        case 0x002:
        case 0x003:
            return sprintf(result_str, "create [ delta = 0x%016x, period = 0x%016x ]", event_extra[0],
                                event_extra[1]);
        case 0x004:
            return sprintf(result_str, "create [ delta = 0x%08x%08x, period = 0x%08x%08x, irq = %d ]",
                                event_extra[1], event_extra[0], event_extra[3],
                                event_extra[2], event_extra[4]);
        case 0x005:
            return sprintf(result_str, "destroy [ tn = %d ]", event_extra[0]);
        case 0x006:
        case 0x007:
        case 0x008:
            return sprintf(result_str, "destroy [ ]");
        case 0x009:
        case 0x00a:
            return sprintf(result_str, "callback [ ]");
        case 0x00b:
            return sprintf(result_str, "int_output = %d, is_master = %d, irq = %d",
                                event_extra[0], event_extra[1], event_extra[2]);
        case 0x00c:
            return sprintf(result_str, "vcpu_kick [ irq = %d ]", event_extra[0]);
        case 0x00d:
            return sprintf(result_str, "is_master = %d, irq = %d", event_extra[0], event_extra[1]);
        case 0x00e:
        case 0x00f:
            return sprintf(result_str, "irq = %d", event_extra[0]);
        case 0x010:
            return sprintf(result_str, "accept_pic_intr = %d, int_output = %d", event_extra[0],
                                event_extra[1]);
        case 0x011:
            return sprintf(result_str, "i8259_target = %d, accept_pic_int = %d", event_extra[0],
                                event_extra[1]);
        default:
            return 0;
    }
}

static int hvm_entryexit_evinfo(const uint32_t event_sub, 
                    const uint32_t *event_extra, char *result_str)
{
    switch (event_sub) {
        //case 0x001:
        //    return sprintf(result_str, "");
        case 0x002:
        case 0x402:
            return sprintf(result_str, "exitcode = 0x%08x, rIP  = 0x%08x", event_extra[0], event_extra[1]);
        case 0x102:
        case 0x502:
            return sprintf(result_str, "exitcode = 0x%08x, rIP  = 0x%08x%08x",
                                event_extra[0], event_extra[2], event_extra[1]);
        //case 0x401:
        //    return sprintf(result_str, "");
        default:
            return 0;
    }
}

static int hvm_handler_evinfo(const uint32_t event_sub, 
                    const uint32_t *event_extra, char *result_str)
{
    switch (event_sub) {
        case 0x001:
            return sprintf(result_str, "errorcode = 0x%02x, virt = 0x%08x", event_extra[1], event_extra[0]);
        case 0x101:
            return sprintf(result_str, "errorcode = 0x%02x, virt = 0x%08x%08x", event_extra[2], event_extra[1],
                                event_extra[0]);
        case 0x002:
            return sprintf(result_str, "errorcode = 0x%02x, virt = 0x%08x", event_extra[0], event_extra[1]);
        case 0x102:
            return sprintf(result_str, "errorcode = 0x%02x, virt = 0x%08x%08x", event_extra[0], event_extra[2],
                                event_extra[1]);
        case 0x003:
            return sprintf(result_str, "vector = 0x%02x, errorcode = 0x%04x", event_extra[0], event_extra[1]);
        case 0x004:
            return sprintf(result_str, "vector = 0x%02x, fake = %d", event_extra[0], event_extra[1]);
        case 0x005:
        case 0x00F:
        case 0x023:
            return sprintf(result_str, "vector = 0x%02x", event_extra[0]);
        case 0x006:
        case 0x007:
            return sprintf(result_str, "port = 0x%04x, size = %d", event_extra[0], event_extra[1]);
        case 0x008:
        case 0x009:
            return sprintf(result_str, "CR# = %d, value = 0x%08x", event_extra[0], event_extra[1]);
        case 0x108:
        case 0x109:
            return sprintf(result_str, "CR# = %d, value = 0x%08x%08x", event_extra[0], event_extra[2],
                                event_extra[1]);
        //case 0x00A:
        //    return sprintf(result_str, "");
        //case 0x00B:
        //    return sprintf(result_str, "");
        case 0x00C:
        case 0x00D:
            return sprintf(result_str, "MSR# = 0x%08x, value = 0x%08x%08x", event_extra[0], 
                            
                                                event_extra[2], event_extra[1]);
        case 0x00E:
            return sprintf(result_str, "func = 0x%08x, eax = 0x%08x, ebx = 0x%08x, ecx=0x%08x, edx = 0x%08x",
                                event_extra[0], event_extra[1], event_extra[2], event_extra[3], event_extra[4]);
        //case 0x010:
        //    return sprintf(result_str, "");
        //case 0x011:
        //    return sprintf(result_str, "");
        case 0x012:
            return sprintf(result_str, "func = 0x%08x", event_extra[0]);
        case 0x013:
            return sprintf(result_str, "intpending = %d", event_extra[0]);
        case 0x014:
            return sprintf(result_str, "is invlpga? = %d, virt = 0x%08x", event_extra[0], event_extra[1]);
        case 0x114:
            return sprintf(result_str, "is invlpga? = %d, virt = 0x%08x%08x", event_extra[0],
                                event_extra[2], event_extra[1]);
        //case 0x015:
        //    return sprintf(result_str, "");
        case 0x016:
        case 0x216:
            return sprintf(result_str, "port = 0x%04x, data = 0x%08x", event_extra[0], event_extra[1]);
        case 0x017:
        case 0x217:
            return sprintf(result_str, "port = 0x%08x, data = 0x%08x", event_extra[0], event_extra[1]);
        //case 0x018:
        //    return sprintf(result_str, "");
        case 0x019:
        case 0x020:
            return sprintf(result_str, "value = 0x%08x", event_extra[0]);
        case 0x119:
        case 0x01a:
            return sprintf(result_str, "value = 0x%08x%08x", event_extra[1], event_extra[0]);
        case 0x021:
            return sprintf(result_str, "gpa = 0x%08x%08x mfn = 0x%08x%08x qual = 0x%04x p2mt = 0x%04x",
                                event_extra[1], event_extra[0], event_extra[3], event_extra[2], 
                                event_extra[4], event_extra[5]);
        default:
            return 0;
    }
}

int get_hvmcls_evinfo(const uint32_t event_id, 
                    const uint32_t *event_extra, char *result_str)
{
    int event_sub = event_id & 0x00000fff;
    switch (GET_EVENT_SUBCLS(event_id)) {
        case GET_EVENT_SUBCLS(TRC_HVM_EMUL):
            return hvm_emul_evinfo(event_sub, event_extra, result_str);
        case GET_EVENT_SUBCLS(TRC_HVM_ENTRYEXIT):
            return hvm_entryexit_evinfo(event_sub, event_extra, result_str);
        case GET_EVENT_SUBCLS(TRC_HVM_HANDLER):
            return hvm_handler_evinfo(event_sub, event_extra, result_str);
        default:
            return 0;
    }
}
