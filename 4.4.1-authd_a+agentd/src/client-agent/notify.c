/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_crypto/md5/md5_op.h"
#include "os_net/os_net.h"
#include "agentd.h"

/* Keeps hash in memory until a change is identified */
static char *g_shared_mg_file_hash = NULL;
/* Keeps the timestamp of the last notification. */
static time_t g_saved_time = 0;

/* Return the names of the files in a directory */
char *getsharedfiles()
{
    unsigned int m_size = 64;
    char *ret;
    os_md5 md5sum;

    if (OS_MD5_File(SHAREDCFG_FILE, md5sum, OS_TEXT) != 0) {
        md5sum[0] = 'x';
        md5sum[1] = '\0';
    }

    /* We control these files, max size is m_size */
    ret = (char *)calloc(m_size + 1, sizeof(char));
    if (ret) {
        snprintf(ret, m_size, "%s merged.mg\n", md5sum);
    }

    // ret = "x\0 merged.mg\n"
    return (ret);
}

#ifndef WIN32
char *get_agent_ip()
{
    char agent_ip[IPSIZE + 1] = { '\0' };
#if defined (__linux__) || defined (__MACH__) || defined (sun) || defined(FreeBSD) || defined(OpenBSD)
    int sock;
    int i;
    static const char * REQUEST = "host_ip";

    for (i = SOCK_ATTEMPTS; i > 0; --i) {
        if (sock = control_check_connection(), sock >= 0) {
            if (OS_SendUnix(sock, REQUEST, strlen(REQUEST)) < 0) {
                mdebug1("Error sending msg to control socket (%d) %s", errno, strerror(errno));
            }
            else{
                if (OS_RecvUnix(sock, IPSIZE, agent_ip) <= 0) {
                    mdebug1("Error receiving msg from control socket (%d) %s", errno, strerror(errno));
                    agent_ip[0] = '\0';
                }
            }

            close(sock);
            break;
        } else {
            mdebug2("Control module not yet available. Remaining attempts: %d", i - 1);
            sleep(1);
        }
    }

    if(sock < 0) {
        mdebug1("Cannot get the agent host's IP because the control module is not available: (%d) %s.", errno, strerror(errno));
    }
#endif
    return strdup(agent_ip);
}
#endif /* !WIN32 */

/* Clear merged hash cache, to be updated in the next iteration.*/
void clear_merged_hash_cache() {
    os_free(g_shared_mg_file_hash);
}

/* Periodically send notification to server */
void run_notify()
{
    char tmp_msg[OS_MAXSTR - OS_HEADER_SIZE + 2];
    static char tmp_labels[OS_MAXSTR - OS_SIZE_2048] = { '\0' };
    os_md5 md5sum;
    time_t curr_time;
    static char agent_ip[IPSIZE + 1] = { '\0' };
    static time_t last_update = 0;
    static const char no_hash_value[] = "x merged.mg\n";

    tmp_msg[OS_MAXSTR - OS_HEADER_SIZE + 1] = '\0';
    curr_time = time(0);

#ifndef ONEWAY_ENABLED
    /* Check if the server has responded */
    // 這邊有一個參數 available_server 是server的有效期限
    // 當超過這個有效期，就要重新handshake一次
    if ((curr_time - available_server) > agt->max_time_reconnect_try) {
        /* If response is not available, set lock and wait for it */
        mwarn(SERVER_UNAV);
        os_setwait();
        w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_NACTIVE);

        /* Send sync message */
        start_agent(0);

        minfo(SERVER_UP);
        os_delwait();
        w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_ACTIVE);
    }
#endif

    /* Check if the agent has to be reconnected */
    // 當強迫超過一定要重新連線的區間時，就要重新做重連線的功能
    if (agt->force_reconnect_interval && (curr_time - last_connection_time) >= agt->force_reconnect_interval) {
        /* Set lock and wait for it */
        minfo("Wazuh Agent will be reconnected because of force reconnect interval");
        os_setwait();
        w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_NACTIVE);

        /* Send sync message */
        start_agent(0);

        os_delwait();
        w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_ACTIVE);
    }

    /* Check if time has elapsed */
    if ((curr_time - g_saved_time) < agt->notify_time) {
        return;
    }
    g_saved_time = curr_time;

    mdebug1("Sending agent notification.");

    /* Send the message
     * Message is going to be the uname\n checksum file\n checksum file\n
     */

    /* Get uname */
    if (!getuname()) {
        merror(MEM_ERROR, errno, strerror(errno));
    }

    /* Format labeled data
     * Limit maximum size of the labels to avoid truncation of the keep-alive message
     * 限制max size of the labels避免keep-alive message被截斷
     */
    if (!tmp_labels[0] && labels_format(agt->labels, tmp_labels, OS_MAXSTR - OS_SIZE_2048) < 0) {
        mwarn("Too large labeled data. Not all labels will be shown in the keep-alive messages.");
    }

    /* Get shared files */
    /* JDelete : 這邊不用傳送shared file了，先不打算實作group的概念
    struct stat stat_fd;
    if (!g_shared_mg_file_hash) {
        // g_shared_mg_file_hash 會是 x\0 merged.mg
        // merged.mg可能是要被group同步用
        g_shared_mg_file_hash = getsharedfiles();
        if (!g_shared_mg_file_hash) {
            merror(MEM_ERROR, errno, strerror(errno));
            return;
        }
    } 
    // Get merged.mg attributes for FILE and put them in BUF:stat_fd
    else if(stat(SHAREDCFG_FILE, &stat_fd) == -1 && ENOENT == errno) {
        clear_merged_hash_cache();
    }*/

    time_t now = time(NULL);
    // 如果上次更新距離現在已經超過參數 main_ip_update_interval 的話就要更新
    if ((now - last_update) >= agt->main_ip_update_interval) {
        // Update agent_ip considering main_ip_update_interval value
        last_update = now;
        char *tmp_agent_ip = get_agent_ip();

        if (tmp_agent_ip) {
            strncpy(agent_ip, tmp_agent_ip, IPSIZE);
            os_free(tmp_agent_ip);
        } else {
           mdebug1("Cannot update host IP.");
           *agent_ip = '\0';
        }
    }
    /* Create message */
    // 進這邊代表有agent_ip，且沒有錯誤。
    if(*agent_ip != '\0' && strcmp(agent_ip, "Err")) {
        char label_ip[60];
        // ex : label_ip 可能是 #"_agent_ip":192.xxx.xxx.xxx
        snprintf(label_ip, sizeof label_ip, "#\"_agent_ip\":%s", agent_ip);
        // 如果上次修改 /etc/shared/agent.conf 的時間超過0，而且md5 hash這個file沒有錯誤的話
        // 就把tmp_msg設定成 : #!-"uname" / "/etc/shared/agent.conf的md5sum" \n "merged.mg的md5 hash值"#"_agent_ip":192.xxx.xxx.xxx
        
        
        /*JDelete : 這邊我要直接註解掉，因為沒有要傳送shared file
        if ((File_DateofChange(AGENTCONFIG) > 0 ) &&
                (OS_MD5_File(AGENTCONFIG, md5sum, OS_TEXT) == 0)) {
            snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "%s%s / %s\n%s%s%s\n", CONTROL_HEADER,
                    getuname(), md5sum, tmp_labels, g_shared_mg_file_hash ? g_shared_mg_file_hash : no_hash_value, label_ip);
        } else {
            snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "%s%s\n%s%s%s\n", CONTROL_HEADER,
                    getuname(), tmp_labels, g_shared_mg_file_hash ? g_shared_mg_file_hash : no_hash_value, label_ip);
        }*/

        // JAdd : 因為沒有要加上shared_file，所以我自己封裝訊息。
        snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "%s%s\n%s%s\n", CONTROL_HEADER, getuname(), 
                    tmp_labels, label_ip);
    }
    // 進這邊代表沒有agent_ip
    else {
        /*JDelete : 這邊我要直接註解掉，因為沒有要傳送shared file
        if ((File_DateofChange(AGENTCONFIG) > 0 ) &&
                (OS_MD5_File(AGENTCONFIG, md5sum, OS_TEXT) == 0)) {
            snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "%s%s / %s\n%s%s\n", CONTROL_HEADER,
                    getuname(), md5sum, tmp_labels, g_shared_mg_file_hash ? g_shared_mg_file_hash : no_hash_value);
        } else {
            snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "%s%s\n%s%s\n", CONTROL_HEADER,
                    getuname(), tmp_labels, g_shared_mg_file_hash ? g_shared_mg_file_hash : no_hash_value);
        }*/
        
        //JAdd : 這邊因為我沒有要加上shared_file，所以我自己封裝訊息 (這邊是沒有ip訊息)
        snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "%s%s\n%s\n", CONTROL_HEADER, getuname(), tmp_labels);
    }

    /* Send status message */
    // 傳送到server
    mdebug2("Sending keep alive: %s", tmp_msg);
    minfo("Sending keep alive: %s", tmp_msg);
    send_msg(tmp_msg, -1);

    w_agentd_state_update(UPDATE_KEEPALIVE, (void *) &curr_time);
    return;
}
