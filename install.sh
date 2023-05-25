# 5/22(一) 針對 Ubuntu Wazuh-Agent/Server 的 os_auth 功能 的 install shell 重擬初版。


### Looking up for the execution directory
cd `dirname $0`

### Looking for echo -n
ECHO="echo -n"
hs=`echo -n "a"`
if [ ! "X$hs" = "Xa" ]; then
    if [ -x /usr/ucb/echo ]; then
        ECHO="/usr/ucb/echo -n"
    elif [ -x /bin/echo ]; then
        ECHO="/bin/echo -n"
    else
        ECHO=echo
    fi
fi

# Initializing vars
SET_DEBUG=""

# Checking for command line arguments
for i in $*; do
    if [ "X$i" = "Xdebug" ]; then
        SET_DEBUG="debug"
    elif [ "X$i" = "Xbinary-install" ]; then
        USER_BINARYINSTALL="yes"
    elif [ "X$i" = "Xhelp" ]; then
        echo "$0 debug"
        echo "$0 binary-install"
        exit 1;
    fi
done

##########
# setEnv_j()
# 新加的部分，把缺失的參數補齊的地方。用以做初步測試。
##########
setEnv_j()
{
    echo "########### JNote : running on install.sh : setEnv_j() ###########"

    # *************************************************
    # ************ copied from <shared.sh> ************
    # *************************************************

    # ************ Line:7-12 ************
    ### Setting up variables
    VERSION_FILE="./src/VERSION"
    REVISION_FILE="./src/REVISION"
    VERSION=`cat ${VERSION_FILE}`
    REVISION=`cat ${REVISION_FILE}`
    UNAME=`uname -snr`

    # ************ Line:16-31 ************ 設定 ME,HOST 的地方
    # JNote : If whoami does not exist, try id
    # If whoami does not exist, try id
    if command -v whoami > /dev/null 2>&1 ; then
        ME=`whoami`
    else
        ME=`id | cut -d " " -f 1`
        if [ "X${ME}" = "Xuid=0(root)" ]; then
            ME="root"
        fi
    fi

    # If hostname does not exist, try 'uname -n'
    if command -v hostname > /dev/null 2>&1 ; then
        HOST=`hostname`
    else
        HOST=`uname -n`
    fi

    # JNote : 抓DNS ip :127.0.0.53
    NAMESERVERS=`cat /etc/resolv.conf | grep "^nameserver" | cut -d " " -sf 2`
    NAMESERVERS2=`cat /etc/resolv.conf | grep "^nameserver" | cut -sf 2`

    # ************ Line:37 ************
    NAME="Wazuh"

    # ************ Line:39-40 ************
    # Default installation directory
    INSTALLDIR="/var/ossec";

    # ************ Line:48-51 ************
    ## Templates
    TEMPLATE="./etc/templates"
    ERROR="errors"
    MSG="messages"

    # ************ Line:59 ************
    ## Predefined file
    PREDEF_FILE="./etc/preloaded-vars.conf"

    # ******************************************************
    # ************ copied from <dist-detect.sh> ************
    # ******************************************************

    # ************ Line:7-12 ************
    # JNote : 這個檔案本來要自動化偵測os+version，我這邊直接指定
    # DISTRIB_RELEASE也直接指定20.04
    DIST_NAME="ubuntu"
    DISTRIB_RELEASE="20.04"
    DIST_VER=$(echo $DISTRIB_RELEASE | sed -rn 's/.*([0-9][0-9])\.[0-9][0-9].*/\1/p')
    DIST_SUBVER=$(echo $DISTRIB_RELEASE | sed -rn 's/.*[0-9][0-9]\.([0-9][0-9]).*/\1/p')


    # **********************************************************************
    # ************ copied from <install.sh> : UseSyscollector() ************
    # **********************************************************************
    # JNote : 這邊直接設定不要 SYSCOLLECTOR
    SYSCOLLECTOR="no"

    # *****************************************************************************************
    # ************ copied from <install.sh> : UseSecurityConfigurationAssessment() ************
    # *****************************************************************************************
    # JNote : 這邊直接設定不要 SECURITY_CONFIGURATION_ASSESSMENT
    SECURITY_CONFIGURATION_ASSESSMENT="no"


    # *****************************************************************
    # ************ copied from <install.sh> : UseSSLCert() ************
    # *****************************************************************
    # JNote : 這邊直接設定要 SSL_CERT
    SSL_CERT="yes"


}

# ************ Line:47-66 ************ install function
##########
# install()
##########
Install()
{
    echo "########### JNote : running on install.sh : Install() ###########"

    echo ""
    echo "4- ${installing}"

    echo ""
    echo "DIR=\"${INSTALLDIR}\""

    # Changing Config.OS with the new C flags
    # Checking if debug is enabled
    if [ "X${SET_DEBUG}" = "Xdebug" ]; then
        CEXTRA="${CEXTRA} -DDEBUGAD"
    fi

    echo "CEXTRA=${CEXTRA}" >> ./src/Config.OS

    MAKEBIN=make

    # ************ Line:99-122 ************ makefile 相關
    # Makefile
    echo " - ${runningmake}"
    echo ""

    cd ./src

    # Binary install will use the previous generated code.
    if [ "X${USER_BINARYINSTALL}" = "X" ]; then
        # Download external libraries if missing
        find external/* > /dev/null 2>&1 || ${MAKEBIN} deps ${ALPINE_DEPS} TARGET=${INSTYPE}

        # Add DATABASE=pgsql or DATABASE=mysql to add support for database
        # alert entry
        ${MAKEBIN} TARGET=${INSTYPE} INSTALLDIR=${INSTALLDIR} ${SYSC_FLAG} ${MSGPACK_FLAG} ${AUDIT_FLAG} ${CPYTHON_FLAGS} -j${THREADS} build

        if [ $? != 0 ]; then
            cd ../
            catError "0x5-build"
        fi
    fi

    # J_Note : 跳過了 update 的部分

    # ************ Line:130-142 ************ makefile 相關
    # Install
    InstallWazuh

    cd ../

    # Install Wazuh ruleset updater
    if [ "X$INSTYPE" = "Xserver" ]; then
        WazuhSetup
    fi

    # Calling the init script to start Wazuh during boot
    runInit $INSTYPE ${update_only}
    runinit_value=$?

    # J_Note : 跳過了 update 的部分


    # ************ Line:153-158 ************ 啟動Wazuh
    if [ $runinit_value = 1 ]; then
        notmodified="yes"
    elif [ "X$START_WAZUH" = "Xyes" ]; then
        echo "Starting Wazuh..."
        UpdateStartOSSEC
    fi
}

# ************ Line:244-319 ************ EnableAuthd(),ConfigureBoot(),SetupLogs()
##########
# EnableAuthd()
##########
EnableAuthd()
{
    echo "########### JNote : running on install.sh : EnableAuthd() ###########"

    # Authd config
    NB=$1
    echo ""
    $ECHO "  $NB - ${runauthd} ($yes/$no) [$yes]: "
    if [ "X${USER_ENABLE_AUTHD}" = "X" ]; then
        read AS
    else
        AS=${USER_ENABLE_AUTHD}
    fi
    echo ""
    case $AS in
        $nomatch)
            AUTHD="no"
            echo "   - ${norunauthd}."
            ;;
        *)
            AUTHD="yes"
            echo "   - ${yesrunauthd}."
            ;;
    esac
}

##########
# ConfigureBoot()
##########
ConfigureBoot()
{
    echo "########### JNote : running on install.sh : ConfigureBoot() ###########"

    NB=$1
    if [ "X$INSTYPE" != "Xagent" ]; then

        echo ""
        $ECHO "  $NB- ${startwazuh} ($yes/$no) [$yes]: "

        if [ "X${USER_AUTO_START}" = "X" ]; then
            read ANSWER
        else
            ANSWER=${USER_AUTO_START}
        fi

        echo ""
        case $ANSWER in
            $nomatch)
                echo "   - ${nowazuhstart}"
                ;;
            *)
                START_WAZUH="yes"
                echo "   - ${yeswazuhstart}"
                ;;
        esac
    fi
}

##########
# SetupLogs()
##########
SetupLogs()
{
    echo "########### JNote : running on install.sh : SetupLogs() ###########"

    NB=$1
    echo ""
    echo "  $NB- ${readlogs}"
    echo ""

    WriteLogs "echo"

    echo ""
    catMsg "0x106-logs"

    if [ "X$USER_NO_STOP" = "X" ]; then
        read ANY
    fi
}


# ************ Line:322-552 ************ configure client/server
##########
# ConfigureClient()
##########
ConfigureClient()
{
    echo "########### JNote : running on install.sh : ConfigureClient() ###########"

    echo ""
    echo "3- ${configuring} $NAME."
    echo ""

    if [ "X${USER_AGENT_SERVER_IP}" = "X" -a "X${USER_AGENT_SERVER_NAME}" = "X" ]; then
        # Looping and asking for server ip or hostname
        while [ 1 ]; do
            $ECHO "  3.1- ${serveraddr}: "
                read ADDRANSWER
            # Is it an IP?
            echo $ADDRANSWER | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" > /dev/null 2>&1
            if [ $? = 0 ]; then
                    echo ""
                SERVER_IP=$ADDRANSWER
                    echo "   - ${addingip} $IP"
                break;
            # Must be a name
            elif [ $? != 0 ]; then
                    echo ""
                HNAME=$ADDRANSWER
                    echo "   - ${addingname} $HNAME"
                break;
            fi
        done
    else
        SERVER_IP=${USER_AGENT_SERVER_IP}
        HNAME=${USER_AGENT_SERVER_NAME}
    fi

    # Set up CA store
    catMsg "0x109-castore"
    AddCAStore

    # Set up the log files
    # SetupLogs "3.7"

    # Write configuration
    #WriteAgent
}

##########
# ConfigureServer()
##########
ConfigureServer()
{
    echo "########### JNote : running on install.sh : ConfigureServer() ###########"

    echo ""
    echo "3- ${configuring} $NAME."

    # Setting up the auth daemon & logs
    if [ "X$INSTYPE" = "Xserver" ]; then
        EnableAuthd "3.7"
        ConfigureBoot "3.8"
        #SetupLogs "3.9"
        #WriteManager
    else
        echo "########### JNote : It should be server not local ###########"
        #ConfigureBoot "3.6"
        #SetupLogs "3.7"
        #WriteLocal
    fi
}

# ************ Line:554-583 ************
##########
# setInstallDir()
##########
setInstallDir()
{
    echo "########### JNote : running on install.sh : setInstallDir() ###########"
    # JNote : USER_DIR 是 predefine 文件裡的設定
    if [ "X${USER_DIR}" = "X" ]; then
        # If we don't have a value in USER_DIR, it means that the user
        # should specify the installation directory.
        while [ 1 ]; do
            echo ""
            $ECHO "2- ${wheretoinstall} [$INSTALLDIR]: "
            read ANSWER
            if [ ! "X$ANSWER" = "X" ]; then
                echo $ANSWER |grep -E "^/[a-zA-Z0-9./_-]{3,128}$">/dev/null 2>&1
                if [ $? = 0 ]; then
                    INSTALLDIR=$ANSWER;
                    break;
                fi
            else
                break;
            fi
        done
    else
        # This else statement handles the case in which it was determined that the installation
        # is an upgrade. So, the USER_DIR variable was previously set with the value of PREINSTALLEDDIR.
        # Another possibility is that USER_DIR could have been set before running the script in
        # order to run an unattended installation.
        INSTALLDIR=${USER_DIR}
    fi
}


# ************ Line:585-598 ************
##########
# setEnv()
##########
setEnv()
{
    echo "########### JNote : running on install.sh : setEnv() ###########"
    echo ""
    echo "    - ${installat} ${INSTALLDIR} ."

    if [ "X$INSTYPE" = "Xagent" ]; then
        CEXTRA="$CEXTRA -DCLIENT"
    elif [ "X$INSTYPE" = "Xlocal" ]; then
        CEXTRA="$CEXTRA -DLOCAL"
    fi
}

# ************ Line:600-626 ************
##########
# askForDelete()
##########
askForDelete()
{
    echo "########### JNote : running on install.sh : askForDelete() ###########"

    if [ -d "$INSTALLDIR" ]; then
        if [ "X${USER_DELETE_DIR}" = "X" ]; then
            echo ""
            $ECHO "    - ${deletedir} ($yes/$no) [$no]: "
            read ANSWER
        else
            ANSWER=${USER_DELETE_DIR}
        fi

        case $ANSWER in
            $yesmatch)
                echo "      Stopping Wazuh..."
                UpdateStopOSSEC
                rm -rf $INSTALLDIR
                if [ ! $? = 0 ]; then
                    echo "Error deleting ${INSTALLDIR}"
                    exit 2;
                fi
                ;;
        esac
    fi
}

##########
# AddCAStore()
##########
AddCAStore()
{
    echo "########### JNote : running on install.sh : AddCAStore() ###########"

    while [ 1 ]
    do
        echo ""
        $ECHO "   - ${addcastore} ($yes/$no)? [$no]: "

        # If white list is set, we don't need to ask it here.
        if [ "X${USER_CA_STORE}" = "X" ]; then
            read ANSWER
        else
            ANSWER=${USER_CA_STORE}
        fi

        if [ "X${ANSWER}" = "X" ] ; then
            ANSWER=$no
        fi

        case $ANSWER in
            $no)
                break;
                ;;
            *)
                SET_CA_STORE="true"
                $ECHO "   - ${castore}"
                if [ "X${USER_CA_STORE}" = "X" ]; then
                    read CA_STORE
                else
                    CA_STORE=${USER_CA_STORE}
                fi

                break;
                ;;
        esac
    done

    # Check the certificate

    if [ -n "$CA_STORE" ]
    then
        if [ -f $CA_STORE ]
        then
            if hash openssl 2>&1 > /dev/null && [ $(date -d "$(openssl x509 -enddate -noout -in $CA_STORE | cut -d = -f 2)" +%s) -lt $(date +%s) ]
            then
                echo ""
                echo "     Warning: the certificate at \"$CA_STORE\" is expired."
            fi
        elif [ ! -d $CA_STORE ]
        then
            echo ""
            echo "     Warning: No such file or directory \"$CA_STORE\"."
        fi
    fi
}


# ************ Line:771 ************ main function
##########
# main()
##########
main()
{
    echo "########### JNote : running on install.sh : main() ###########"

    # ************ Line:777 ************ 
    LANGUAGE="en"

    # ************ Line:780 ************ 
    . ./src/init/functions.sh

    # ************ Line:782-785 ************
    # JNote : 這邊去讀predefine的文件，裡面包含一些設定
    # 會用到的像是
    # Reading pre-defined file
    if [ ! `isFile ${PREDEF_FILE}` = "${FALSE}" ]; then
        . ${PREDEF_FILE}
    fi

    # ************ Line:827-831 ************ 
    . ./src/init/language.sh
    . ./src/init/init.sh
    . ./src/init/wazuh/wazuh.sh
    . ${TEMPLATE}/${LANGUAGE}/messages.txt
    . ./src/init/inst-functions.sh
    
    # ************ Line:835-837 ************ 這邊讀取版本的檔案
    if [ `isFile ${VERSION_FILE}` = "${FALSE}" ]; then
        catError "0x1-location";
    fi

    # ************ Line:839-842 ************ 確定權限root
    # Must be root
    if [ ! "X$ME" = "Xroot" ]; then
        catError "0x2-beroot";
    fi

    # ************ Line:851-860 ************ 初始化訊息列印
    # Initial message
    echo " $NAME $VERSION (Rev. $REVISION) ${installscript} - https://www.wazuh.com"
    catMsg "0x101-initial"
    echo ""
    echo "  - $system: $UNAME (${DIST_NAME} ${DIST_VER}.${DIST_SUBVER})"
    echo "  - $user: $ME"
    echo "  - $host: $HOST"
    echo ""
    echo ""
    echo "  -- $hitanyorabort --"


    # ************ Line:866 ************ 呼叫update.sh
    . ./src/init/update.sh

    # JNote : 以下關於update的相關動作我都先刪掉了

    # ************ Line:926-933 ************ 設定安裝類型
    # Setting up the installation type
    # JNote : 我註解掉 hybrid 相關的東東
    serverm=`echo ${server} | cut -b 1`
    localm=`echo ${local} | cut -b 1`
    agentm=`echo ${agent} | cut -b 1`
    helpm=`echo ${help} | cut -b 1`


    # ************ Line:935-982 ************ 
    # 如果沒有設定 USER_INSTALL_TYPE，詢問安裝者
    # 這邊的意思就是如果沒有pre define 文件就直接用問的 好讚
    # If user install type is not set, ask for it.
    if [ "X${USER_INSTALL_TYPE}" = "X" ]; then

        # Loop for the installation options
        while [ 1 ]
        do
            echo ""
            $ECHO "1- ${whattoinstall} "


            read ANSWER
            case $ANSWER in

                ${helpm}|${help})
                    catMsg "0x102-installhelp"
                ;;

                ${server}|${serverm}|"manager"|"m")
                    echo ""
                    echo "  - ${serverchose}."
                    INSTYPE="server"
                    break;
                ;;

                ${agent}|${agentm}|"a")
                    echo ""
                    echo "  - ${clientchose}."
                    INSTYPE="agent"
                    break;
                ;;

                ${hybrid}|${hybridm})
                    echo ""
                    echo "  - ${serverchose} (hybrid)."
                    INSTYPE="server"
                    HYBID="go"
                    break;
                ;;
                ${local}|${localm})
                    echo ""
                    echo "  - ${localchose}."
                    INSTYPE="local"
                    break;
                ;;
            esac
        done

    else
        INSTYPE=${USER_INSTALL_TYPE}
    fi
    
    # ************ Line:985-992 ************ 設定安裝目錄、環境、及刪除已存在檔案
    # Setting up the installation directory
    setInstallDir
    # Setting up the environment
    setEnv
    # Ask to remove the current installation if exists
    # askForDelete

    # ************ Line:994-1005 ************ 根據安裝類型設定系統
    # Configuring the system (based on the installation type)
    if [ "X${update_only}" = "X" ]; then
        if [ "X$INSTYPE" = "Xserver" ]; then
            ConfigureServer
        elif [ "X$INSTYPE" = "Xagent" ]; then
            ConfigureClient
        elif [ "X$INSTYPE" = "Xlocal" ]; then
            ConfigureServer
        else
            catError "0x4-installtype"
        fi
    fi

    # ************ Line:1007-1009 ************ 開始安裝
    # Installing (calls the respective script
    # -- InstallAgent.sh or InstallServer.sh
    Install

    # ************ Line:1011-1025 ************ 一些使用者訊息
    # User messages
    echo ""
    echo " - ${configurationdone}."
    echo ""
    echo " - ${tostart}:"
    echo "      $INSTALLDIR/bin/wazuh-control start"
    echo ""
    echo " - ${tostop}:"
    echo "      $INSTALLDIR/bin/wazuh-control stop"
    echo ""
    echo " - ${configat} $INSTALLDIR/etc/ossec.conf"
    echo ""

    # ************ Line:1078-1082 ************ 一些使用者訊息
    catMsg "0x103-thanksforusing"

    if [ "X$notmodified" = "Xyes" ]; then
        catMsg "0x105-noboot"
        echo "      $INSTALLDIR/bin/wazuh-control start"
        echo ""
    fi

}


### 補齊環境的缺失設定及參數
setEnv_j

# ************ Line:1091-1092 ************ call main function
### Calling main function where everything happens
main

exit 0

#### exit ? ###
