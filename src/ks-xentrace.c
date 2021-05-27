/**
 * XenTrace data processing interface for KernelShark - Copyright (C) 2021
 * Giuseppe Eletto <peppe.eletto@gmail.com>
 * Dario Faggioli  <dfaggioli@suse.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 * USA
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
#include <trace.h>
// XenTrace-Parser
#include "xentrace-event.h"
#include "xentrace-parser.h"
// Events formatting
#include "events/events.h"

#ifdef DEBUG
#define DBG_PRINTF(_format, ...) fprintf(stdout, \
                    "[XenTrace DEBUG] "__func__": "_format, __VA_ARGS__);
#endif

#define TASK_MAX_LEN 16

#define ENV_XEN_CPUHZ "XEN_CPUHZ"
#define ENV_XEN_ABSTS "XEN_ABSTS"

#define QHZ_FROM_HZ(_hz) (((_hz) << 10) / 1000000000)
#define DEFAULT_CPU_HZ 2400000000LL
#define GHZ 1000000000LL
#define MHZ 1000000LL
#define KHZ 1000LL

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

    char *result_str = malloc(TASK_MAX_LEN);
    if (!result_str)
        return NULL;

    xt_domain dom = event->dom;
    int result_len = 0;

    switch (dom.id) {
        case XEN_DOM_IDLE:
            result_len = snprintf(result_str, TASK_MAX_LEN, "idle/v%u", dom.vcpu);
            break;
        case XEN_DOM_DFLT:
            result_len = snprintf(result_str, TASK_MAX_LEN, "default/v?");
            break;
        default:
            result_len = snprintf(result_str, TASK_MAX_LEN, "d%u/v%u", dom.id, dom.vcpu);
            break;
    }

    return (result_len > 0) ? result_str : NULL;
}

/**
 *
 */
static const int get_event_id(struct kshark_data_stream *stream,
                                const struct kshark_entry *entry)
{
    if (entry->visible & KS_PLUGIN_UNTOUCHED_MASK) {
        xt_event *event = xtp_get_event(I.parser, entry->offset);
        return event ? (event->rec).id : -EFAULT;
    }

    return KS_EMPTY_BIN;
}

/**
 * 
 */
static char *get_event_name(struct kshark_data_stream *stream,
                                const struct kshark_entry *entry)
{
    xt_event *event = xtp_get_event(I.parser, entry->offset);
    char *result_str = malloc(STR_EVNAME_MAXLEN);
    if ( !(event && result_str) )
        return NULL;

    uint32_t event_id = (event->rec).id;
    int result_len = 0;

    switch ( GET_EVENT_CLS(event_id) ) {
        // General trace
        case GET_EVENT_CLS(TRC_GEN):
            result_len = get_basecls_evname(event_id, result_str);
            break;
        // Xen Scheduler trace
        case GET_EVENT_CLS(TRC_SCHED):
            result_len = get_schedcls_evname(event_id, result_str);
            break;
        // Xen DOM0 operation trace
        case GET_EVENT_CLS(TRC_DOM0OP):
            result_len = get_dom0cls_evname(event_id, result_str);
            break;
        // Xen HVM trace
        case GET_EVENT_CLS(TRC_HVM):
            result_len = get_hvmcls_evname(event_id, result_str);
            break;
        // Xen memory trace
        case GET_EVENT_CLS(TRC_MEM):
            result_len = get_memcls_evname(event_id, result_str);
            break;
        // Xen PV traces
        case GET_EVENT_CLS(TRC_PV):
            result_len = get_pvcls_evname(event_id, result_str);
            break;
        // Xen shadow tracing
        case GET_EVENT_CLS(TRC_SHADOW):
            result_len = get_shdwcls_evname(event_id, result_str);
            break;
        // Xen hardware-related traces
        case GET_EVENT_CLS(TRC_HW):
            result_len = get_hwcls_evname(event_id, result_str);
            break;
    }

    #ifdef DEBUG
    if (result_len > STR_EVNAME_MAXLEN)
        DBG_PRINTF("result_len(%d) is greater than the maximum length!\n", result_len);
    #endif

    if (result_len < 1) {
        result_len = EVNAME(result_str, "unknown (0x%08x)", event_id);
        if (result_len < 1) {
            free(result_str);
            return NULL;
        }
    }

    return result_str;
}

/**
 * 
 */
static char *get_info(struct kshark_data_stream *stream,
                            const struct kshark_entry *entry)
{
    xt_event *event = xtp_get_event(I.parser, entry->offset);
    char *result_str = malloc(STR_EVINFO_MAXLEN);
    if ( !(event && result_str) )
        return NULL;

    xt_record e_record = event->rec;
    int result_len = 0;

    switch ( GET_EVENT_CLS(e_record.id) ) {
        // General trace
        case GET_EVENT_CLS(TRC_GEN):
            result_len = get_basecls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen Scheduler trace
        case GET_EVENT_CLS(TRC_SCHED):
            result_len = get_schedcls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen DOM0 operation trace
        case GET_EVENT_CLS(TRC_DOM0OP):
            result_len = get_dom0cls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen HVM trace
        case GET_EVENT_CLS(TRC_HVM):
            result_len = get_hvmcls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen memory trace
        case GET_EVENT_CLS(TRC_MEM):
            result_len = get_memcls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen PV traces
        case GET_EVENT_CLS(TRC_PV):
            result_len = get_pvcls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen shadow tracing
        case GET_EVENT_CLS(TRC_SHADOW):
            result_len = get_shdwcls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen hardware-related traces
        case GET_EVENT_CLS(TRC_HW):
            result_len = get_hwcls_evinfo(e_record.id, e_record.extra, result_str);
            break;
    }

    #ifdef DEBUG
    if (result_len > STR_EVINFO_MAXLEN)
        DBG_PRINTF("result_len(%d) is greater than the maximum length!\n", result_len);
    #endif

    if (result_len < 1) {
        free(result_str);
        return NULL;
    }

    return result_str;
}

/**
 * 
 */
static char *dump_entry(struct kshark_data_stream *stream,
                            const struct kshark_entry *entry)
{
    double ev_ts = (double)entry->ts / 1e9;
    char *ev_task = get_task(stream, entry),
        *ev_name  = get_event_name(stream, entry),
        *ev_info  = get_info(stream, entry),
        *result_str;

    int result_len = asprintf(&result_str, "%.6f - %s - %s [ %s ]", 
                            ev_ts, ev_task, ev_name, ev_info);

    free(ev_task);
    free(ev_name);
    free(ev_info);

    return (result_len > 0) ? result_str : NULL;
}

/**
 *
 */
static int64_t tsc_to_ns(uint64_t tsc)
{
    // TODO Check absolute time conversion
    if (I.first_tsc) // if "XEN_ABSTS" is NOT set
        tsc = (tsc - I.first_tsc) << 10;
    return tsc / I.cpu_qhz;
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
    struct kshark_entry **rows = malloc(sizeof(struct kshark_entry*) * n_events);

    xt_event *event;
    while ( (event = xtp_next_event(I.parser)) ) {
        // Utility ptrs
        xt_record *rec = &event->rec;

        // Initialize KS row
        rows[pos] = calloc(1, sizeof(struct kshark_entry));

        // Populate members of the KS row
        rows[pos]->stream_id = stream->stream_id;
        rows[pos]->visible = 0xff;
        rows[pos]->offset = pos;

        rows[pos]->event_id = rec->id % 16; // FIXME  int16_t < uint32_t:28  ¯\_(ツ)_/¯
        rows[pos]->cpu = event->cpu;
        rows[pos]->ts  = tsc_to_ns(rec->tsc);

        if ((event->dom).id != XEN_DOM_IDLE) {
            int task_id = ((event->dom).id == XEN_DOM_DFLT) ? 
                                XEN_DOM_DFLT : (event->dom).u32 + 1;
            kshark_hash_id_add(stream->tasks, task_id);
            rows[pos]->pid = task_id;
        } // else 0

        // Go next
        ++pos;
    }

    *data_rows = rows;
    return n_events;
}

static uint64_t parse_cpu_hz(char *arg) {
    char *next_ptr;
    float hz_base = strtof(arg, &next_ptr);

    if (next_ptr == arg) {
        fprintf(stderr, "[XenTrace WARN] Invalid cpu_hz \"%s\". The default value will be used.\n", arg);
        return DEFAULT_CPU_HZ;
    }

    switch (*next_ptr) {
        case '\0':
            return (uint64_t) hz_base;
        case 'G':
            return hz_base * GHZ;
        case 'M':
            return hz_base * MHZ;
        case 'K':
            return hz_base * KHZ;
        default:
            fprintf(stderr, "[XenTrace WARN] Unknown suffix '%c'. The default value will be used.\n", *next_ptr);
            return DEFAULT_CPU_HZ;
    }
}

/**
 *
 */
static void read_env_vars()
{
    // Read trace CPU Hz (or set default val)
    char *env_base_hz = secure_getenv(ENV_XEN_CPUHZ);
    I.cpu_hz = env_base_hz ? parse_cpu_hz(env_base_hz) : DEFAULT_CPU_HZ;
    I.cpu_qhz = QHZ_FROM_HZ(I.cpu_hz);

    // Save the tsc of the first event to
    // perform the calc of the relative ts.
    char *env_abs_ts = secure_getenv(ENV_XEN_ABSTS);
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
    interface->get_pid  = get_pid;
    interface->get_event_id = get_event_id;
    interface->get_event_name = get_event_name;
    interface->get_task = get_task;
    interface->get_info = get_info;

    interface->dump_entry   = dump_entry;
    interface->load_entries = load_entries;
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
    int fread_ok = fread(&event_id, sizeof(event_id), 1, fp) == 1;
    fclose(fp);

    // TRC_TRACE_CPU_CHANGE should be the first record
    return fread_ok && ((event_id & 0x0fffffff) == TRC_TRACE_CPU_CHANGE);
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
    if ( !(I.parser && n_events) ) {
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