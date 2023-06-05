/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 *  The stack smashing protector defeats some BoF via: gcc -fstack-protector
 *  Reference: http://gcc.gnu.org/onlinedocs/gcc-4.1.2/cpp.pdf
 */

#if defined(__GNUC__) && (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 1) && (__GNUC_PATCHLEVEL__ >= 2)) || \
                          ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 2)) || \
                           (__GNUC__ >= 5))

/* Heuristically enable the stack protector on sensitive functions */
#define __SSP__ 1

/* FORTIFY_SOURCE is RedHat / Fedora specific */
#define FORTIFY_SOURCE
#endif

#ifndef SHARED_H
#define SHARED_H

#ifndef LARGEFILE64_SOURCE
#define LARGEFILE64_SOURCE
#endif /* LARGEFILE64_SOURCE */

#ifndef FILE_OFFSET_BITS
#define FILE_OFFSET_BITS 64
#endif /* FILE_OFFSET_BITS */

/* Global headers */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>

#ifndef WIN32
#include <sys/wait.h>
#include <sys/resource.h>

// Only Linux and FreeBSD need mount.h */
#if defined(Linux) || defined(FreeBSD)
#include <sys/mount.h>
#endif

/* HPUX does not have select.h */
#ifndef HPUX
#include <sys/select.h>
#endif

#include <sys/utsname.h>
#endif /* WIN32 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>

/* The mingw32 builder used by travis.ci can't find glob.h
 * Yet glob must work on actual win32.
 */
#ifndef __MINGW32__
#include <glob.h>
#endif

#ifndef WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include <direct.h>
#endif

#ifdef __cplusplus
#include <atomic>
#define _Atomic(T) std::atomic<T>
#else
#ifdef hpux
// TODO: remove this line after upgrading GCC on HP-UX
#define _Atomic(T) T
#endif
#endif

#include <time.h>
#include <errno.h>
#include <libgen.h>

#include "defs.h"
#include "help.h"

#include "os_err.h"

#ifndef LARGEFILE64_SOURCE
#define LARGEFILE64_SOURCE
#endif /* LARGEFILE64_SOURCE */

#ifndef FILE_OFFSET_BITS
#define FILE_OFFSET_BITS 64
#endif /* FILE_OFFSET_BITS */

/* Global portability code */

#ifdef SOLARIS
#include <limits.h>
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;

#ifndef va_copy
#define va_copy __va_copy
#endif

#endif /* SOLARIS */

#if defined(HPUX) || defined(DOpenBSD)
#include <limits.h>
typedef uint64_t u_int64_t;
typedef int int32_t;
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;

#define MSG_DONTWAIT 0
#endif

#ifdef Darwin
typedef int sock2len_t;
#endif

#ifndef WIN32
#define CloseSocket(x) close(x)
#endif

#ifdef WIN32
typedef int uid_t;
typedef int gid_t;
typedef int socklen_t;
#define sleep(x) Sleep((x) * 1000)
#define srandom(x) srand(x)
#define lstat(x,y) stat(x,y)
#define CloseSocket(x) closesocket(x)
void WinSetError();
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;

#define MSG_DONTWAIT    0

#ifndef PROCESSOR_ARCHITECTURE_AMD64
#define PROCESSOR_ARCHITECTURE_AMD64 9
#endif
#endif /* WIN32 */

#ifdef AIX
#define MSG_DONTWAIT MSG_NONBLOCK
#endif

#if defined(__GNUC__) && __GNUC__ >= 7
#define fallthrough __attribute__ ((fallthrough))
#else
#define fallthrough ((void) 0)
#endif

/* IPv4 structure */
typedef struct _os_ipv4 {
    unsigned int ip_address;
    unsigned int netmask;
} os_ipv4;

/* IPv6 structure */
typedef struct _os_ipv6 {
    uint8_t ip_address[16];
    uint8_t netmask[16];
} os_ipv6;

/* IP structure */
typedef struct _os_ip {
    char *ip;
    union {
        os_ipv4 *ipv4;
        os_ipv6 *ipv6;
    };
    bool is_ipv6;
} os_ip;


extern const char *__local_name;
/*** Global prototypes ***/
/*** These functions will exit on error. No need to check return code ***/

/* for calloc: x = calloc(4,sizeof(char)) -> os_calloc(4,sizeof(char),x) */
#define os_calloc(x,y,z) ((z = (__typeof__(z)) calloc(x,y)))?(void)1:merror_exit(MEM_ERROR, errno, strerror(errno))

#define os_strdup(x,y) ((y = strdup(x)))?(void)1:merror_exit(MEM_ERROR, errno, strerror(errno))

#define os_malloc(x,y) ((y = (__typeof__(y)) malloc(x)))?(void)1:merror_exit(MEM_ERROR, errno, strerror(errno))

#define os_free(x) if(x){free(x);x=NULL;}

#define os_realloc(x,y,z) ((z = (__typeof__(z))realloc(x,y)))?(void)1:merror_exit(MEM_ERROR, errno, strerror(errno))

#define os_clearnl(x,p) if((p = strrchr(x, '\n')))*p = '\0';

#define w_fclose(x) if (x) { fclose(x); x=NULL; }

#define w_strdup(x,y) ({ int retstr = 0; if (x) { os_strdup(x, y);} else retstr = 1; retstr;})

#define sqlite_strdup(x,y) ({ if (x) { os_strdup(x, y); } else (void)0; })

#define w_strlen(x) ({ size_t ret = 0; if (x) ret = strlen(x); ret;})

// Calculate the number of elements within an array.
// Only static arrays allowed.
#define array_size(array) (sizeof(array)/sizeof(array[0]))

#ifdef CLIENT
#define isAgent 1
#else
#define isAgent 0
#endif

#ifndef WAZUH_UNIT_TESTING
#define FOREVER() 1
#else
#include "unit_tests/wrappers/common.h"
#endif

// JNote : 這邊我有改過，把一些header拿掉。

#include "debug_op.h"
#include "wait_op.h" // mq_op.c會用到os_wait_predicate(), os_wait()
#include "agent_op.h" // log_builder.c會用到 control_check_connection()
#include "file_op.h"
#include "fs_op.h" // ./config/syscheck-config.h 會用到fs_set
#include "mem_op.h" // syscheck-config.c 會用到 os_IsStrOnArray(), key.c 會用到 memset_secure(), expression.c+syscheck_op.c會用到w_FreeArray()
#include "math_op.h" // hash_op.c會用到 os_getprime()
#include "mq_op.h" // wazuh_modules/agent_upgrade/agent/wm_agent_upgrade_agent.c 會用到INFINITE_OPENQ_ATTEMPTS
#include "privsep_op.h" // read-agents.c會用到 w_ctime()
#include "pthreads_op.h"
#include "regex_op.h"
#include "sig_op.h" // os_auth/main-client.c會用到 StartSIG()
#include "list_op.h"
#include "hash_op.h" // ./analysisd/decoders/decoder.h,./config/syscheck-config.h,./analysisd/rules.h 會用到OSHash
#include "rbtree_op.h" // ./headers/sec.h 會用到 rbtree
#include "queue_op.h"  // ./analysisd/rules.h,./analysisd/rules.h 會用到 'w_queue_t'
#include "queue_linked_op.h" // ./headers/sec.h 會用到 w_linked_queue_node_t,w_linked_queue_t
// #include "bqueue_op.h"
#include "store_op.h" // ./analysisd/decoders/decoder.h,./analysisd/rules.h 會用到OSStrore
// #include "rc.h"
#include "ar.h" // AS_ONLY, REMOTE_AGENT, SPECIFIC_AGENT, ALL_AGENTS, REMOTE_AR, LOCAL_AR
#include "validate_op.h" // client-config.c會用到 OS_IsValidIP()、OS_ExpandIPv6, log_builder.c會用到getDefine_Int
// #include "file-queue.h"
// #include "json-queue.h"
#include "read-agents.h" // validate.c會用到
// #include "report_op.h"
#include "string_op.h" // log_builder.c會用到wstr_escape_json()
#include "randombytes.h" // os_crtypt/shared/msgs.c,addagent/validate.c 會用到os_random()
#include "labels_op.h" // struct wlabel_t
#include "time_op.h" // debug_op.c會用到w_get_timestamp()
#include "vector_op.h" // ./headers/../syscheckd/syscheck.h會用到W_Vector
#include "exec_op.h" // wfd_t struct, #define W_BIND_STDOUT 001
// #include "json_op.h"
// #include "notify_op.h"
#include "version_op.h" // file_op.h呼叫的
// #include "utf8_op.h"
#include "rwlock_op.h" // log_builder.h會用到 struct rwlock_t
#include "log_builder.h" // mq_op.c會用到 struct log_builder_t

#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"

#include "error_messages/error_messages.h"
#include "error_messages/debug_messages.h"
#include "error_messages/information_messages.h"
#include "error_messages/warning_messages.h"
// #include "custom_output_search.h"
#include "url.h"
// #include "yaml2json.h"
// #include "cluster_utils.h"
#include "auth_client.h"
// #include "os_utils.h"
// #include "schedule_scan.h"
// #include "bzip2_op.h"
#include "enrollment_op.h"
// #include "buffer_op.h"
#include "atomic.h" // ./headers/../syscheckd/syscheck.h 會用到 atomic_int_t struct

#endif /* SHARED_H */
