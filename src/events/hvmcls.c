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

static int hvm_emul_evname(const uint32_t event_sub, char ***event_name)
{
    switch (event_sub) {
        case 0x001:
        case 0x005:
            return asprintf(*event_name, "hpet");
        case 0x002:
        case 0x006:
        case 0x009:
            return asprintf(*event_name, "pit");
        case 0x003:
        case 0x007:
            return asprintf(*event_name, "rtc");
        case 0x004:
        case 0x008:
        case 0x00a:
            return asprintf(*event_name, "vlapic");
        case 0x00b:
            return asprintf(*event_name, "vpic_update_int_output");
        case 0x00c:
            return asprintf(*event_name, "vpic");
        case 0x00d:
            return asprintf(*event_name, "__vpic_intack");
        case 0x00e:
            return asprintf(*event_name, "vpic_irq_positive_edge");
        case 0x00f:
            return asprintf(*event_name, "vpic_irq_negative_edge");
        case 0x010:
            return asprintf(*event_name, "vpic_ack_pending_irq");
        case 0x011:
            return asprintf(*event_name, "vlapic_accept_pic_intr");
        default:
            return 0;
    }
}

static int hvm_entryexit_evname(const uint32_t event_sub, char ***event_name)
{
    switch (event_sub) {
        case 0x001:
            return asprintf(*event_name, "VMENTRY");
        case 0x002:
            return asprintf(*event_name, "VMEXIT");
        case 0x102:
            return asprintf(*event_name, "VMEXIT");
        case 0x401:
            return asprintf(*event_name, "nVMENTRY");
        case 0x402:
            return asprintf(*event_name, "nVMEXIT");
        case 0x502:
            return asprintf(*event_name, "nVMEXIT");
        default:
            return 0;
    }
}

static int hvm_handler_evname(const uint32_t event_sub, char ***event_name)
{
    switch (event_sub) {
        case 0x101:
            return asprintf(*event_name, "PF_XEN");
        case 0x002:
            return asprintf(*event_name, "PF_INJECT");
        case 0x102:
            return asprintf(*event_name, "PF_INJECT");
        case 0x003:
            return asprintf(*event_name, "INJ_EXC");
        case 0x004:
            return asprintf(*event_name, "INJ_VIRQ");
        case 0x005:
            return asprintf(*event_name, "REINJ_VIRQ");
        case 0x006:
            return asprintf(*event_name, "IO_READ");
        case 0x007:
            return asprintf(*event_name, "IO_WRITE");
        case 0x008:
            return asprintf(*event_name, "CR_READ");
        case 0x108:
            return asprintf(*event_name, "CR_READ");
        case 0x009:
            return asprintf(*event_name, "CR_WRITE");
        case 0x109:
            return asprintf(*event_name, "CR_WRITE");
        case 0x00A:
            return asprintf(*event_name, "DR_READ");
        case 0x00B:
            return asprintf(*event_name, "DR_WRITE");
        case 0x00C:
            return asprintf(*event_name, "MSR_READ");
        case 0x00D:
            return asprintf(*event_name, "MSR_WRITE");
        case 0x00E:
            return asprintf(*event_name, "CPUID");
        case 0x00F:
            return asprintf(*event_name, "INTR");
        case 0x010:
            return asprintf(*event_name, "NMI");
        case 0x011:
            return asprintf(*event_name, "SMI");
        case 0x012:
            return asprintf(*event_name, "VMMCALL");
        case 0x013:
            return asprintf(*event_name, "HLT");
        case 0x014:
            return asprintf(*event_name, "INVLPG");
        case 0x114:
            return asprintf(*event_name, "INVLPG");
        case 0x015:
            return asprintf(*event_name, "MCE");
        case 0x016:
            return asprintf(*event_name, "IOPORT_READ");
        case 0x216:
            return asprintf(*event_name, "IOPORT_WRITE");
        case 0x017:
            return asprintf(*event_name, "MMIO_READ");
        case 0x217:
            return asprintf(*event_name, "MMIO_WRITE");
        case 0x018:
            return asprintf(*event_name, "CLTS");
        case 0x019:
            return asprintf(*event_name, "LMSW");
        case 0x119:
            return asprintf(*event_name, "LMSW");
        case 0x01a:
            return asprintf(*event_name, "RDTSC");
        case 0x020:
            return asprintf(*event_name, "INTR_WINDOW");
        case 0x021:
            return asprintf(*event_name, "NPF");
        case 0x023:
            return asprintf(*event_name, "TRAP");
        default:
            return 0;
    }
}

int get_hvmcls_evname(const uint32_t event_id, char ***event_name)
{
    int event_sub = event_id & 0x00000fff;
    switch (GET_EVENT_SUBCLS(event_id)) {
        case GET_EVENT_SUBCLS(TRC_HVM_EMUL):
            return hvm_emul_evname(event_sub, event_name);
        case GET_EVENT_SUBCLS(TRC_HVM_ENTRYEXIT):
            return hvm_entryexit_evname(event_sub, event_name);
        case GET_EVENT_SUBCLS(TRC_HVM_HANDLER):
            return hvm_handler_evname(event_sub, event_name);
        default:
            return 0;
    }
}

int get_hvmcls_evinfo(const uint32_t event_id, 
                    const uint32_t *event_extra, char ***event_info)
{
    return 0;
}
