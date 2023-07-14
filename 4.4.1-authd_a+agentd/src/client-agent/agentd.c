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
#include "agentd.h"
#include "os_net/os_net.h"


/* Start the agent daemon */
void AgentdStart(int uid, int gid, const char *user, const char *group)
{
    int rc = 0;
    int maxfd = 0;
    fd_set fdset;
    struct timeval fdtimeout;

    available_server = 0;

    /* Initial random numbers must happen before chroot */
    srandom_init();

    /* Initialize sender */
    sender_init();

    /* Going Daemon */
    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Set group ID */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    if(agt->enrollment_cfg && agt->enrollment_cfg->enabled) {
        // If autoenrollment is enabled, we will avoid exit if there is no valid key
        OS_PassEmptyKeyfile();
    } else {
        /* Check auth keys */
        if (!OS_CheckKeys()) {
            merror_exit(AG_NOKEYS_EXIT);
        }
    }
    /* Read private keys  */
    minfo(ENC_READ);
    OS_ReadKeys(&keys, W_DUAL_KEY, 0);

    minfo("Using notify time: %d and max time to reconnect: %d", agt->notify_time, agt->max_time_reconnect_try);
    if (agt->force_reconnect_interval) {
        minfo("Using force reconnect interval, Wazuh Agent will reconnect every %ld %s", w_seconds_to_time_value(agt->force_reconnect_interval), w_seconds_to_time_unit(agt->force_reconnect_interval, TRUE));
    }
    
    // 取得OS的資料，如OS platform/version/系統資料等等
    if (!getuname()) {
        merror(MEM_ERROR, errno, strerror(errno));
    } else {
        minfo("Version detected -> %s", getuname());
    }

    /* Try to connect to server */
    // 打開queue/sockets/.wait，寫進一個數字"1"後關閉，是一個global lock，直到os_delwait來unlock
    os_setwait();

    /* Create the queue and read from it. Exit if fails. */
    // m_queue 是 queue/sockets/queue
    if ((agt->m_queue = StartMQ(DEFAULTQUEUE, READ, 0)) < 0) {
        merror_exit(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
    }

#ifdef HPUX
    {
        int flags;
        flags = fcntl(agt->m_queue, F_GETFL, 0);
        fcntl(agt->m_queue, F_SETFL, flags | O_NONBLOCK);
    }
#endif

    maxfd = agt->m_queue;
    agt->sock = -1;

    /* Create PID file - "wazuh-agentd"*/
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    os_random();

    /* Ignore SIGPIPE, it will be detected on recv */
    signal(SIGPIPE, SIG_IGN);

    /* Launch rotation thread */
    // 用來翻頁log用的，include : ossec.log, ossec.json
    rotate_log = getDefine_Int("monitord", "rotate_log", 0, 1);
    if (rotate_log) {
        w_create_thread(w_rotate_log_thread, (void *)NULL);
    }

    /* Launch dispatch thread */
    // default agt->buffer會是 1 
    if (agt->buffer){
        // 先allocate一塊mem來用
        buffer_init();
        
        // Send messages from buffer to the server
        // 這邊是用來確認buffer的使用狀況
        w_create_thread(dispatch_buffer, (void *)NULL);
    } else {
        minfo(DISABLED_BUFFER);
    }

    /* Configure and start statistics */
    /* JDelete : 先把寫狀態的thread關掉
    w_agentd_state_init();
    // 寫目前的狀態
    w_create_thread(state_main, NULL);
    */

    /* Set max fd for select */
    if (agt->sock > maxfd) {
        maxfd = agt->sock;
    }

    /* Connect to the execd queue */
    if (agt->execdq == 0) {
        if ((agt->execdq = StartMQ(EXECQUEUE, WRITE, 1)) < 0) {
            minfo("Unable to connect to the active response "
                   "queue (disabled).");
            agt->execdq = -1;
        }
    }

    // 做agent跟server的handshake
    start_agent(1);

    // unlink queue/sockets/.wait
    os_delwait();

    /* JDelete : 先把寫狀態的地方註解掉
    w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_ACTIVE);
    */

    // Ignore SIGPIPE signal to prevent the process from crashing
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);

    // Start request module
    /* JComment : request module 目前還不是很清楚request在做什麼，但跟queue/sockets/agent有關係，看起來是在跟server之間溝通
    req_init();

    w_create_thread(req_receiver, NULL);
    */

    /* Send agent stopped message at exit */
    // 設定離開的時候要執行的function
    atexit(send_agent_stopped_message);

    /* Send first notification */
    // 算是跟server更新自己的狀況用的
    // 會用來做兩件事 : 
    //     1) 做handshake if 超過 reconnection time
    //     2) 傳送keep-alive msg (agent notify) to server
    // 
    run_notify();

    /* Maxfd must be higher socket +1 */
    maxfd++;

    /* Monitor loop */
    while (1) {

        /* Continuously send notifications */
        // 會用來做兩件事 : 1) 做handshake if 超過 reconnection time
        //                 2) 傳送keep-alive msg (agent notify) to server
        // 10秒內才會做一次
        run_notify();

        // agt->sock 應該就是server的socket fd
        // 如果agt->sock >= maxfd的話
        if (agt->sock > maxfd - 1) {
            maxfd = agt->sock + 1;
        }

        /* Monitor all available sockets from here */
        // fdset是一個fd set, 裡面可放置很多需要監看的fd
        // FD_ZERO - 是用來清空這個fdset用的
        FD_ZERO(&fdset);
        // FD_SET:fdset是用來在fdset中新增一個fd:agt->sock
        FD_SET(agt->sock, &fdset);
        FD_SET(agt->m_queue, &fdset);

        // 設定select參數的timeout時間，時間是一秒。
        fdtimeout.tv_sec = 1;
        fdtimeout.tv_usec = 0;

        /* Wait with a timeout for any descriptor */
        // select function是用來在non-blocking中，當有一個sokcet有信號時通知你
        // maxfd : 要被監聽fd的總數，他比所有fd set中的fd最大值+1
        // fdset : 是可讀的fd set
        rc = select(maxfd, &fdset, NULL, NULL, &fdtimeout);
        if (rc == -1) {
            merror_exit(SELECT_ERROR, errno, strerror(errno));
        } 
        // rc is the number of read descriptors
        else if (rc == 0) {
            // 如果沒有可讀的fd就重來
            continue;
        }

        /* For the receiver */
        // 到這邊就代表有可讀的fd
        // FD_ISSET 是用來判斷agt->sock是否還在fdset中
        // 
        if (FD_ISSET(agt->sock, &fdset)) {

            // 這邊會接收來自server的訊息，可能會收到11種不同的訊息，包含 :
            //   1. Ar cmd                    (need)
            //   2. force_reconnect           (need)
            //   3. Syscheck                  (no need)
            //   4. fim_file                  (no need)
            //   5. fim_registry              (no need)
            //   6. syscollector_             (no need)
            //   7. Ack from server           (need)
            //   8. Request(req) from server  (no need)
            //   9. sca_dump                  (no need)
            //   10. File update msg          (no need)
            //   11. Close file msg           (no need)
            // 目前只先處理需要的部分，其他都comment掉了
            if (receive_msg() < 0) {
                // 進來這邊代表連線server有error
                w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_NACTIVE);
                merror(LOST_ERROR);
                os_setwait();
                start_agent(0);
                minfo(SERVER_UP);
                os_delwait();
                w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_ACTIVE);
            }
        }

        /* For the forwarder */
        // 如果是來自logcollector的話就forward資料到mq等待別人幫忙傳資料
        // Receive a message locally on the agent and forward it to the manager
        
        /* JComment : 這邊負責接收event跟forward給
        if (FD_ISSET(agt->m_queue, &fdset)) {
            EventForward();
        }
        */
        
    }
}
