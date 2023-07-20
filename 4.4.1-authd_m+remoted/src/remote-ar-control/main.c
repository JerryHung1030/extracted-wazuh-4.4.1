/* Module name : remote-ar-control
 * Description : Test for sending remote ar action
 * Author : CSTI - Jerry Hung
 */

/* **************************** 參數說明 ****************************
*  arq        : 開啟 /queue/alerts/ar 的 UDS 
*  ar         : 說明對哪一種類型的哪一台主機(也可以是全部)做什麼動作，觸發了什麼規則
*   |- agent_id    : 
*   |- ar_cmd      : 
*   |    |- timeout_allowed : 
*   |    |- name            : 
*   |    |- executable      : 
*   |    |- extra_args      : 
*   |- command     : 
*   |- level       : 
*   |- location    : 目標位置
*   |- name        : AR動作的name
*   |- rules_group : 
*   |- rules_id    : 
*   |- timeout     : 
*  c_agent_id : 3位數的agent_id
*  msg        : 
*  exec_msg   : 說明對哪一種類型的哪一台主機(也可以是全部)做什麼動作，觸發了什麼規則的"完整訊息"
*/ 

/*  **************************** 參數舉例 ****************************
*  arq         : 
*  ar          : 
*   |- agent_id    : 
*   |- ar_cmd      : 
*   |    |- timeout_allowed : 
*   |    |- name            : 
*   |    |- executable      : 
*   |    |- extra_args      : 
*   |- command     : 
*   |- level       : 
*   |- location    : REMOTE_AGENT | AS_ONLY | ALL_AGENTS | SPECIFIC_AGENT
*   |- name        : 
*   |- rules_group : 
*   |- rules_id    : 
*   |- timeout     : 
*  **************************** 參數舉例 ****************************
*  c_agent_id  : 001 | 002 | .....
*   |- msg = {\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"restart-wazuh0\",\"parameters\":{\"extra_args\":[],\"alert\":[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]}}
*         |- name : 跟cluster有關的node_name, 如果有的話就是node01, node02, ....,
*         |-        但如果沒有定義的話會是 undefined
*         |- module : 就保持 wazuh-analysisd 就好了
*         |- command : restart-wazuh0 | 
*  **************************** final 要傳的msg ****************************
*  exec_msg    : temp_msg + " " + msg
*   |- temp_msg     : ex - (local_source) [] NNS 002
*         |- 第1個N : N-NONE
*         |- 第2個N : N-NONE, R-REMOTE
*         |- 第3個S : N-NONE, S-Specific
*         |- 002    : agent_id
*/

#ifndef ARGV0
#define ARGV0 "remote-ar-control"
#endif

#if defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif


// JNote : 把我需要的.h include進來
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
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

#include "os_net/os_net.h"
#include "file_op.h"
#include "privsep_op.h"
#include "debug_op.h"
#include "sig_op.h"
#include "mq_op.h"
#include "defs.h"
#include "os_err.h"

/* Active response queue */
static int arq = 0;

// Global variable to set whether to exit the loop
int running = 1;

// Signal handler function to catch the Ctrl+C signal and set the exit flag
void signal_handler(int sig) {
    if (sig == SIGINT) {
        running = 0;
    }
}

// Function to check if a string is a valid IPv4 address
bool isValidIpAddress(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

// Function to check if a string contains only numeric digits
int isNumeric(const char *str) {
    while (*str) {
        if (!isdigit(*str)) {
            return 0;
        }
        str++;
    }
    return 1;
}

void getCurrentTimestamp(char *timestamp, int maxSize) {
    time_t now;
    struct tm timeinfo;
    struct timespec spec;
    int milliseconds;

    // Get the current time
    now = time(NULL);

    // Convert the time to UTC time
    gmtime_r(&now, &timeinfo);

    // Set the output time format
    strftime(timestamp, maxSize, "%Y-%m-%dT%H:%M:%S", &timeinfo);

    // Get the milliseconds separately and add them to the timestamp
    clock_gettime(CLOCK_REALTIME, &spec);
    milliseconds = spec.tv_nsec / 1000000;
    snprintf(timestamp + 19, maxSize - 19, ".%03d+0000", milliseconds);
}

/*
// Print help statement
__attribute__((noreturn))
static void help_analysisd(char * home_path)
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", OSSECCONF);
    print_out("    -D <dir>    Directory to chroot and chdir into (default: %s)", home_path);
    print_out(" ");
    os_free(home_path);
    exit(1);
}
*/

// JAdd : Move from exec.c-send_exec_msg()
void r_ar_send_exec_msg(int *socket, const char *queue_path, const char *exec_msg) {
    static int conn_error_sent = 0;

    if (*socket < 0) {
        if ((*socket = StartMQ(queue_path, WRITE, 1)) < 0) {
            if (conn_error_sent == 0){
                merror(QUEUE_ERROR, queue_path, strerror(errno));
                conn_error_sent = 1;
            }

            return;
        } else {
            conn_error_sent = 0;
        }
    }

    int rc = 0;
    if ((rc = OS_SendUnix(*socket, exec_msg, 0)) < 0) {
        if (rc == OS_SOCKBUSY) {
            merror(EXEC_QUEUE_BUSY);
        }
        OS_CloseSocket(*socket);
        *socket = -1;
        merror(EXEC_QUEUE_CONNECTION_ERROR, queue_path);
    }
}

int main(int argc, char **argv)
{
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    uid_t uid;
    gid_t gid;

    signal(SIGINT, signal_handler); // Set the signal handler to catch the Ctrl+C signal

    /* Set the name */
    OS_SetName(ARGV0);

    // Define current working directory
    char * home_path = w_homedir(argv[0]);

    mdebug1(WAZUH_HOMEDIR, home_path);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Found user */
    mdebug1(FOUND_USER);

    /* Set the group */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Chroot */
    if (Privsep_Chroot(home_path) < 0) {
        merror_exit(CHROOT_ERROR, home_path, errno, strerror(errno));
    }
    nowChroot();

    /* Set the user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    /* Verbose message */
    mdebug1(PRIVSEP_MSG, home_path, user);
    os_free(home_path);


    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create the PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    // 接下來是真正用來傳送ar forward的地方

    if ((arq = StartMQ(ARQUEUE, WRITE, 1)) < 0) {
        merror(ARQ_ERROR);
    } else {
        minfo(CONN_TO, ARQUEUE, "active-response");
    }

    minfo("Active response Init completed.");

    // 做一個假訊息，format可以參考上面
    // module remoted會幫忙加上來標頭- "#!-execd "

    char agent_id[4];
    char ar[20];
    char command[20];
    char ip[100];
    char unblock[50];
    char unblock_msg[20];
    char exec_msg[500]; // Declare the exec_msg string
    char timestamp[50]; // Make sure this size is enough to hold the timestamp
    
    /* Startup message */
    minfo(STARTUP_MSG, (int)getpid());

    while (running) {

        /* Startup message */
        printf("############################################################# \n");
        printf("#################### START A NEW SECTION #################### \n");
        printf("############################################################# \n");

        // Check if the input is a 3-digit numeric string
        strcpy(agent_id, ""); // Initialize agent_id
        printf("Please input 3-digits agent id (make sure that agent exist!!): \n");
        scanf("%s", agent_id);
        while (strlen(agent_id) != 3 || !isNumeric(agent_id)) {
            printf("Syntax error, please try again!!\n");
            scanf("%s", agent_id);
        }

        // Check if the input is "route-null" or "restart"
        strcpy(ar, ""); // Initialize ar
        printf("Which active response action do you want to perform (route-null, restart): \n");
        scanf("%s", ar);
        while (strcmp(ar, "route-null") != 0 && strcmp(ar, "restart") != 0) {
            printf("Command not found, please try again!!\n");
            scanf("%s", ar);
        }

        if (strcmp(ar, "route-null") == 0) {
            
            // Check unblock or not
            strcpy(unblock, ""); // Initialize unblock
            strcpy(unblock_msg, ""); // Initialize unblock
            printf("Do you want to unblock or block ? (enter \"unblock\" or \"block\")\n");
            scanf("%s", unblock);
            while (strcmp(unblock, "unblock") != 0 && strcmp(unblock, "block") != 0) {
                printf("Syntax error, please enter \"unblock\" or \"block\"\n");
                scanf("%s", unblock);
            }

            // 如果要unblock這邊就多一個unblock的json obj string
            if (strcmp(unblock, "unblock") == 0) {
                strcpy(unblock_msg, ",\"unblock\":\"true\"");
            }

            // Check if the input is a valid IPv4 address
            strcpy(ip, ""); // Initialize ip
            printf("Which IP do you want to route-null? \n");
            scanf("%s", ip);
            while (!isValidIpAddress(ip)) {
                printf("Syntax error, please enter a valid IPv4 address.\n");
                scanf("%s", ip);
            }
            
            // get nowtime
            getCurrentTimestamp(timestamp, sizeof(timestamp));

            // create command name
            strcpy(command, "!route-null"); // Initialize ar

            // Perform the action for "route-null" with the provided IP address
            sprintf(exec_msg, "(local_source) [] NNS %s {\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"!route-null\",\"parameters\":{\"extra_args\":[],\"alert\":{\"timestamp\":\"%s\",\"rule\":{\"level\":5,\"description\":\"Test by jerry.\",\"id\":\"000\"},\"data\":{\"srcip\":\"%s\"}}%s}}", agent_id, timestamp, ip, unblock_msg);
            printf("sending 'route-null' cmd with IP: %s\n", ip);
            minfo("sending 'route-null' cmd with IP: %s\n", ip);
        }
        else if (strcmp(ar, "restart") == 0) {

            // get nowtime
            getCurrentTimestamp(timestamp, sizeof(timestamp));

            sprintf(exec_msg, "(local_source) [] NNS %s {\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"restart-wazuh\",\"parameters\":{\"extra_args\":[],\"alert\":[{\"timestamp\":\"%s\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]}}", agent_id, timestamp);
            printf("sending 'restart' cmd.\n");
            minfo("sending 'restart' cmd.");
        }

        // Pass this fake message to arqueue
        r_ar_send_exec_msg(&arq, ARQUEUE, exec_msg);
    }

    return 0;
}