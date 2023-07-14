/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* remote daemon
 * Listen to remote packets and forward them to the analysis system
 */

#include "shared.h"
#include "os_net/os_net.h"
#include "remoted.h"

#define WM_STRCAT_NO_SEPARATOR 0

/* Global variables */
keystore keys;
remoted logr;
char* node_name;
rlim_t nofile;
int tcp_keepidle;
int tcp_keepintvl;
int tcp_keepcnt;

/* Handle remote connections */
void HandleRemote(int uid)
{
    const int position = logr.position;
    int recv_timeout;    //timeout in seconds waiting for a client reply
    char * str_protocol = NULL;

    /* JNote : 小知識科普 - 一般來說TCP會設定keepalive的機制
     *    tcp_keepalive_time   : 一個發送心跳包的週期，DEFAUL-7200s(2hrs)
     *    tcp_keepalive_intvl  : keepalive探測封包的發送間隔，DEFAUL-75s 
     *    tcp_keepalive_probes : 在tcp_keepalive_time之後，沒有接收到對方確認，繼續發送探測封包次數，DEFAUL-9次
     */
    recv_timeout = getDefine_Int("remoted", "recv_timeout", 1, 60);
    tcp_keepidle = getDefine_Int("remoted", "tcp_keepidle", 1, 7200);
    tcp_keepintvl = getDefine_Int("remoted", "tcp_keepintvl", 1, 100);
    tcp_keepcnt = getDefine_Int("remoted", "tcp_keepcnt", 1, 50);

    /* If syslog connection and allowips is not defined, exit */
    /* JNote : 目前不會跑這邊了，因為我把syslog的地方擋下來了。可以直接跳過
    if (logr.conn[position] == SYSLOG_CONN) {
        if (logr.allowips == NULL) {
            minfo(NO_SYSLOG);
            exit(0);
        } else {
            os_ip **tmp_ips;

            tmp_ips = logr.allowips;
            while (*tmp_ips) {
                minfo("Remote syslog allowed from: '%s'", (*tmp_ips)->ip);
                tmp_ips++;
            }
        }
    }*/

    // Set resource limit for file descriptors
    // 設定最小跟最大的fd數量
    {
        nofile = getDefine_Int("remoted", "rlimit_nofile", 1024, 1048576);
        struct rlimit rlimit = { nofile, nofile };

        if (setrlimit(RLIMIT_NOFILE, &rlimit) < 0) {
            merror("Could not set resource limit for file descriptors to %d: %s (%d)", (int)nofile, strerror(errno), errno);
        }
    }

    /* If TCP is enabled then bind the TCP socket */
    if (logr.proto[position] & REMOTED_NET_PROTOCOL_TCP) {
        // tcp_sock 就會是 server負責連線的socket了
        logr.tcp_sock = OS_Bindporttcp(logr.port[position], logr.lip[position], logr.ipv6[position]);

        if (logr.tcp_sock < 0) {
            merror_exit(BIND_ERROR, logr.port[position], errno, strerror(errno));
        }
        else if (logr.conn[position] == SECURE_CONN) {
            // 這邊會設定tcp 這邊的keep alive資料
            if (OS_SetKeepalive(logr.tcp_sock) < 0) {
                merror("OS_SetKeepalive failed with error '%s'", strerror(errno));
            }
#ifndef CLIENT
            else {
                OS_SetKeepalive_Options(logr.tcp_sock, tcp_keepidle, tcp_keepintvl, tcp_keepcnt);
            }
#endif
            if (OS_SetRecvTimeout(logr.tcp_sock, recv_timeout, 0) < 0) {
                merror("OS_SetRecvTimeout failed with error '%s'", strerror(errno));
            }
        }
    }
    /* If UDP is enabled then bind the UDP socket */
    /* 這邊目前不會用到 
    if (logr.proto[position] & REMOTED_NET_PROTOCOL_UDP) {
        // Using UDP. Fast, unreliable... perfect
        logr.udp_sock = OS_Bindportudp(logr.port[position], logr.lip[position], logr.ipv6[position]);

        if (logr.udp_sock < 0) {
            merror_exit(BIND_ERROR, logr.port[position], errno, strerror(errno));
        }
    }*/


    /* Revoke privileges */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, USER, errno, strerror(errno));
    }

    /* Create PID */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Start up message */
    // If TCP is enabled
    if (logr.proto[position] & REMOTED_NET_PROTOCOL_TCP) {
        wm_strcat(&str_protocol, REMOTED_NET_PROTOCOL_TCP_STR, WM_STRCAT_NO_SEPARATOR);
    }
    // If UDP is enabled
    /* JDelete : 這邊目前不會用到
    if (logr.proto[position] & REMOTED_NET_PROTOCOL_UDP) {
        wm_strcat(&str_protocol, REMOTED_NET_PROTOCOL_UDP_STR, (str_protocol == NULL) ? WM_STRCAT_NO_SEPARATOR : ',');
    }*/

    /* This should never happen */
    // str_protocol 會是 "TCP"
    if (str_protocol == NULL) {
        merror_exit(REMOTED_NET_PROTOCOL_NOT_SET);
    }

    minfo(STARTUP_MSG " Listening on port %d/%s (%s).",
        (int)getpid(),
        logr.port[position],
        str_protocol,
        logr.conn[position] == SECURE_CONN ? "secure" : "syslog");
    os_free(str_protocol);

    /* If secure connection, deal with it */
    if (logr.conn[position] == SECURE_CONN) {
        HandleSecure();
    }
    else if (logr.proto[position] == REMOTED_NET_PROTOCOL_TCP) {
        merror_exit("JError : it should not be set to syslog-TCP!!!");
        // JDelete : 先刪掉syslogTCP的功能，不能有這個
        // HandleSyslogTCP();
    }
    else { /* If not, deal with syslog */
        merror_exit("JError : it should not be set to syslog-UDP!!!");
        // JDelete : 先刪掉syslogUDP的功能，不能有這個
        // HandleSyslog();
    }
}