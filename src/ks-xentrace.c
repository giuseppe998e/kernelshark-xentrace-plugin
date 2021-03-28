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

#ifdef DEBUG
#define DBG_PRINTF(_format, ...) (fprintf(stdout, "[XenTrace DEBUG] %s: ", __func__), \
                                    fprintf(stdout, _format, __VA_ARGS__));
#endif

#define ENV_XEN_CPUHZ "XEN_CPUHZ"
#define ENV_XEN_ABSTS "XEN_ABSTS"

#define MAX_EVNAME_LENGTH 32
#define MAX_EVINFO_LENGTH 128

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
    char *result_str = malloc(sizeof(*result_str) * MAX_EVNAME_LENGTH);
    int result_ok = 0;

    switch ( GET_EVENT_CLS(event_id) ) {
        // General trace
        case GET_EVENT_CLS(TRC_GEN):
            result_ok = get_basecls_evname(event_id, result_str);
            break;
        // Xen Scheduler trace
        case GET_EVENT_CLS(TRC_SCHED):
            result_ok = get_schedcls_evname(event_id, result_str);
            break;
        // Xen DOM0 operation trace
        case GET_EVENT_CLS(TRC_DOM0OP):
            result_ok = get_dom0cls_evname(event_id, result_str);
            break;
        // Xen HVM trace
        case GET_EVENT_CLS(TRC_HVM):
            result_ok = get_hvmcls_evname(event_id, result_str);
            break;
        // Xen memory trace
        case GET_EVENT_CLS(TRC_MEM):
            result_ok = get_memcls_evname(event_id, result_str);
            break;
        // Xen PV traces
        case GET_EVENT_CLS(TRC_PV):
            result_ok = get_pvcls_evname(event_id, result_str);
            break;
        // Xen shadow tracing
        case GET_EVENT_CLS(TRC_SHADOW):
            result_ok = get_shdwcls_evname(event_id, result_str);
            break;
        // Xen hardware-related traces
        case GET_EVENT_CLS(TRC_HW):
            result_ok = get_hwcls_evname(event_id, result_str);
            break;
    }

    if (result_ok < 1) {
        result_ok = sprintf(result_str, "unknown (0x%08x)", event_id);
        if (result_ok < 1)
            return NULL;
    }

    #ifdef DEBUG
    if (result_ok > MAX_EVNAME_LENGTH)
        DBG_PRINTF("result_ok(%d) is greater than the maximum length!\n", result_ok);
    #endif

    return result_str;
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

    xt_record e_record = event->rec;
    char *result_str = malloc(sizeof(*result_str) * MAX_EVINFO_LENGTH);
    int result_ok = 0;

    switch ( GET_EVENT_CLS(e_record.id) ) {
        // General trace
        case GET_EVENT_CLS(TRC_GEN):
            result_ok = get_basecls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen Scheduler trace
        case GET_EVENT_CLS(TRC_SCHED):
            result_ok = get_schedcls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen DOM0 operation trace
        case GET_EVENT_CLS(TRC_DOM0OP):
            result_ok = get_dom0cls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen HVM trace
        case GET_EVENT_CLS(TRC_HVM):
            result_ok = get_hvmcls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen memory trace
        case GET_EVENT_CLS(TRC_MEM):
            result_ok = get_memcls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen PV traces
        case GET_EVENT_CLS(TRC_PV):
            result_ok = get_pvcls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen shadow tracing
        case GET_EVENT_CLS(TRC_SHADOW):
            result_ok = get_shdwcls_evinfo(e_record.id, e_record.extra, result_str);
            break;
        // Xen hardware-related traces
        case GET_EVENT_CLS(TRC_HW):
            result_ok = get_hwcls_evinfo(e_record.id, e_record.extra, result_str);
            break;
    }

    #ifdef DEBUG
    if (result_ok > MAX_EVINFO_LENGTH)
        DBG_PRINTF("result_ok(%d) is greater than the maximum length!\n", result_ok);
    #endif

    return result_ok > 0 ? result_str : NULL;
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