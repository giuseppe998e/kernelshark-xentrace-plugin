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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "trace.h"
#include "libkshark.h"
#include "libkshark-plugin.h"
#include "xentrace-parser.h"

#define _GNU_SOURCE
#define NOTIMPL      fprintf(stderr, "[XenTrace Plugin] Function \"%s(..)\" NOT yet implemented!\n", __func__);

static const char *format_name = "xentrace_binary";

/**
 * TODO ...
 */
static const int get_pid(struct kshark_data_stream *stream,
                    const struct kshark_entry *entry)
{
    NOTIMPL // TODO
    return 0;
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
    NOTIMPL // TODO
    return NULL;
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
    NOTIMPL // TODO
    return 0;
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
    uint32_t event_id = 0;

    FILE *fp = fopen(file, "rb");
    fread(&event_id, sizeof(uint32_t), 1, fp);
    fclose(fp);

    event_id &= 0x0fffffff;
    return TRC_TRACE_CPU_CHANGE == event_id;
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
    stream->interface = calloc(1, sizeof(struct kshark_generic_stream_interface));
    if (!stream->interface)
        return -ENOMEM;

    stream->interface->type = KS_GENERIC_DATA_INTERFACE;
    init_methods(stream->interface);

    return 0;
}

/**
 * Unloads plugin.
 */
void KSHARK_INPUT_DEINITIALIZER(struct kshark_data_stream *stream)
{}
