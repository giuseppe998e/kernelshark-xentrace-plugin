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

#ifndef __KSXT_EVENTS
#define __KSXT_EVENTS

#include <stdint.h>

#include "trace.h"

#define GET_EVENT_CLS(e)    ((e) >> TRC_CLS_SHIFT)
#define GET_EVENT_SUBCLS(e) ((e) >> TRC_SUBCLS_SHIFT)

// 32 chars + '\0'
#define STR_EVNAME_MAXLEN 33
// #define STR_EVNAME_SIZE (sizeof(char) * STR_EVNAME_MAXLEN) ~~ 33
#define EVNAME(_str, _format, ...) snprintf(_str, STR_EVNAME_MAXLEN, \
                                                _format, ##__VA_ARGS__)

// 128 chars + '\0'
#define STR_EVINFO_MAXLEN 129
// #define STR_EVINFO_SIZE (sizeof(char) * STR_EVINFO_MAXLEN) ~~ 129
#define EVINFO(_str, _format, ...) snprintf(_str, STR_EVINFO_MAXLEN, \
                                                _format, ##__VA_ARGS__)

// General trace | basecls.c
int get_basecls_evname(const uint32_t, char*);
int get_basecls_evinfo(const uint32_t, const uint32_t*, char*);

// Xen Scheduler trace | schedcls.c
int get_schedcls_evname(const uint32_t, char*);
int get_schedcls_evinfo(const uint32_t, const uint32_t*, char*);

// Xen DOM0 operation trace | domzcls.c
int get_dom0cls_evname(const uint32_t, char*);
int get_dom0cls_evinfo(const uint32_t, const uint32_t*, char*);

// Xen HVM trace | hvmcls.c
int get_hvmcls_evname(const uint32_t, char*);
int get_hvmcls_evinfo(const uint32_t, const uint32_t*, char*);

// Xen memory trace | memcls.c
int get_memcls_evname(const uint32_t, char*);
int get_memcls_evinfo(const uint32_t, const uint32_t*, char*);

// Xen PV traces | pvcls.c
int get_pvcls_evname(const uint32_t, char*);
int get_pvcls_evinfo(const uint32_t, const uint32_t*, char*);

// Xen shadow tracing | shdwcls.c
int get_shdwcls_evname(const uint32_t, char*);
int get_shdwcls_evinfo(const uint32_t, const uint32_t*, char*);

// Xen hardware-related | hwcls.c
int get_hwcls_evname(const uint32_t, char*);
int get_hwcls_evinfo(const uint32_t, const uint32_t*, char*);

#endif