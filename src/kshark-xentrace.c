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

#include "trace.h"
#include "libkshark.h"
#include "libkshark-plugin.h"
#include "xentrace-parser.h"

#define NOTIMPL fprintf(stderr, "[XenTrace Plugin] Function \"%s(..)\" NOT yet implemented!\n", __func__);

static xen_trace xtrace;

static const char *format_name = "xentrace_binary";

/**
 * TODO ...
 */
static const int get_pid(struct kshark_data_stream *stream,
                    const struct kshark_entry *entry)
{
    return entry->pid;
}

/**
 * TODO ...
 */
static char *get_task(struct kshark_data_stream *stream,
                    const struct kshark_entry *entry)
{
    NOTIMPL // TODO
    return NULL;
}

/**
 * ...
 */
static char *get_event_name(struct kshark_data_stream *stream,
                    const struct kshark_entry *entry)
{
    char *event_str;
    int pret = asprintf(&event_str, "%s/0x%08x", format_name, entry->event_id);

    if (pret <= 0)
        return NULL;

    return event_str;
}

/**
 * TODO ...
 */
static char *dump_entry(struct kshark_data_stream *stream,
                    const struct kshark_entry *entry)
{
    NOTIMPL // TODO
    return NULL;
}

/**
 * Loads the content of the XenTrace binary file.
 */
static ssize_t load_entries(struct kshark_data_stream *stream,
                    struct kshark_context *kshark_ctx,
                    struct kshark_entry ***data_rows)
{
    ssize_t events_count = (ssize_t)xen_events_count(xtrace);
    struct kshark_entry **rows = calloc(events_count, sizeof(struct kshark_entry*));

    int i = 0;
    int16_t current_cpu = 0;

    xen_event *event;
    while ( (event = xen_next_event(xtrace)) ) {
        if (event->id == TRC_TRACE_CPU_CHANGE)
            current_cpu = event->extra[0];

        rows[i] = malloc(sizeof(struct kshark_entry));

		rows[i]->visible = event->in_cycles ? 0xff : 0x00; // Filter events with no cycles/timestamp
		rows[i]->stream_id = stream->stream_id;
        rows[i]->offset = 0;

		rows[i]->event_id = event->id;
		rows[i]->cpu = current_cpu;
		rows[i]->pid = 0; // TODO ??
		rows[i]->ts  = event->in_cycles ? (int64_t)event->cycles : 0;

        ++i;
    }

    xen_free_trace(xtrace);

    *data_rows = rows;
    return events_count;
}

/**
 * Initializes all methods used to process XENTRACE data.
 */
static void init_methods(struct kshark_generic_stream_interface *interface)
{
    interface->get_pid = get_pid;
	interface->get_task = get_task;
	interface->get_event_name = get_event_name;

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
    int fret = fread(&event_id, sizeof(event_id), 1, fp) == 1;
    fclose(fp);

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

    xtrace = xen_load_trace(stream->file);
    if (!xtrace) {
        free(interface);
        return -ENOMEM;
    }

    xen_load_events(xtrace);
	stream->n_cpus   = xen_cpus_count(xtrace);
	stream->n_events = xen_events_count(xtrace);
	stream->idle_pid = 0; // TODO ??

    init_methods(interface);

    return 0;
}

/**
 * Unloads plugin.
 */
void KSHARK_INPUT_DEINITIALIZER(struct kshark_data_stream *stream)
{}
