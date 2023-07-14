/* Module name : remote-ar-control
 * Description : Test for sending remote ar action
 * Author : CSTI - Jerry Hung
 */

#ifndef ARGV0
#define ARGV0 "remote-ar-control"
#endif

/*
#include "shared.h"
#include <time.h>
*/
#if defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif
/*
#include "alerts/alerts.h"
#include "alerts/getloglocation.h"
#include "os_execd/execd.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"
#include "active-response.h"
#include "config.h"
#include "limits.h"
#include "rules.h"
#include "mitre.h"
#include "stats.h"
#include "eventinfo.h"
#include "accumulator.h"
#include "analysisd.h"
#include "fts.h"
#include "cleanevent.h"
#include "output/jsonout.h"
#include "labels.h"
#include "state.h"
#include "syscheck_op.h"
#include "lists_make.h"
*/

// JNote : 把我需要的.h include進來
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

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

/*
// To translate between month (int) to month (char)
static const char *(month[]) = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                  };

// CPU Info
static int cpu_cores;

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

typedef struct test_struct {
    Eventinfo *lf;
    active_response *ar;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1, sizeof(test_struct_t), init_data);
    os_calloc(1, sizeof(Eventinfo), init_data->lf);
    os_calloc(1, sizeof(DynamicField), init_data->lf->fields);
    os_calloc(1, sizeof(*init_data->lf->generated_rule), init_data->lf->generated_rule);
    os_calloc(1, sizeof(OSDecoderInfo), init_data->lf->decoder_info);
    os_calloc(1, sizeof(active_response), init_data->ar);
    os_calloc(1, sizeof(*init_data->ar->ar_cmd), init_data->ar->ar_cmd);

    init_data->lf->fields[FIM_FILE].value = "/home/vagrant/file/n44.txt";
    init_data->lf->srcip = NULL;
    init_data->lf->dstuser = NULL;
    init_data->lf->time.tv_sec = 160987966;
    init_data->lf->generated_rule->sigid = 554;
    init_data->lf->location = "(ubuntu) any->syscheck";
    init_data->lf->agent_id = "001";
    init_data->lf->decoder_info->name = "syscheck_event";

    init_data->ar->name = "restart-wazuh0";
    init_data->ar->ar_cmd->extra_args = NULL;
    init_data->ar->location = 0;
    init_data->ar->agent_id = "002";
    init_data->ar->command = "restart-wazuh";

    *state = init_data;

    test_mode = 1;

    return OS_SUCCESS;
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

    /*
    // Initialize Active response
    AR_Init();
    if (AR_ReadConfig(cfg) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }
    mdebug1(ASINIT);

    // Fix Config.ar
    Config.ar = ar_flag;
    if (Config.ar == -1) {
        Config.ar = 0;
    }
    */

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

    /*
    int i;

    // Stats
    RuleInfo *stats_rule = NULL;
    stats_rule = zerorulemember(STATS_MODULE, Config.stats, 0, 0, 0, 0, 0, 0, &os_analysisd_last_events);

    // JNote : Starting to Test remote ar
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;

    char *version = "Wazuh v4.4.1";
    data->ar->location = SPECIFIC_AGENT;

    const char *alert_info = "[{\"timestamp\":\"2023-07-10T12:00:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]";
    char *node = NULL;

    os_strdup("node01", node);

    Config.ar = 1;

    wlabel_t *labels = NULL;
    os_calloc(2, sizeof(wlabel_t), labels);

    os_strdup("_wazuh_version", labels[0].key);
    os_strdup(version, labels[0].value);

    ar->agent_id = 
    ar->ar_cmd = 
    ar->command = 
    ar->level = 
    ar->location = SPECIFIC_AGENT;
    ar->name = 
    ar->rules_group =
    ar->rules_id =
    ar->timeout = 
    */

    // 接下來是真正用來傳送ar forward的地方

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

    /* Waiting the ARQ to settle */
    sleep(3);
    if ((arq = StartMQ(ARQUEUE, WRITE, 1)) < 0) {
        merror(ARQ_ERROR);
    } else {
        minfo(CONN_TO, ARQUEUE, "active-response");
    }

    mdebug1("Active response Init completed.");

    /* Startup message */
    minfo(STARTUP_MSG, (int)getpid());

    //int sock = -1;
    
    // 做一個假訊息，format可以參考上面
    // 標頭要是"#!-execd " module remoted會幫忙加上來 
    char *exec_msg = "(local_source) [] NNS 001 {\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"restart-wazuh\",\"parameters\":{\"extra_args\":[],\"alert\":[{\"timestamp\":\"2023-07-11T12:00:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]}}";
    
    r_ar_send_exec_msg(&arq, ARQUEUE, exec_msg);

    while (1) {
        sleep(30);
        minfo("JTest : remote-ar-control is alive!!! do something later~");
    }

    exit(0);
}