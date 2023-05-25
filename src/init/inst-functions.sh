LOCALFILES_TEMPLATE="./etc/templates/config/generic/localfile-logs/*.template"
AUTH_TEMPLATE="./etc/templates/config/generic/auth.template"


##########
# WriteLogs()
##########
WriteLogs()
{
  echo "########### JNote : running on inst-function.sh : WriteLogs() ###########"

  LOCALFILES_TMP=`cat ${LOCALFILES_TEMPLATE}`
  for i in ${LOCALFILES_TMP}; do
      field1=$(echo $i | cut -d\: -f1)
      field2=$(echo $i | cut -d\: -f2)
      field3=$(echo $i | cut -d\: -f3)
      if [ "X$field1" = "Xskip_check_exist" ]; then
          SKIP_CHECK_FILE="yes"
          LOG_FORMAT="$field2"
          FILE="$field3"
      else
          SKIP_CHECK_FILE="no"
          LOG_FORMAT="$field1"
          FILE="$field2"
      fi

      # Check installation directory
      if [ $(echo $FILE | grep "INSTALL_DIR") ]; then
        FILE=$(echo $FILE | sed -e "s|INSTALL_DIR|${INSTALLDIR}|g")
      fi

      # If log file present or skip file
      if [ -f "$FILE" ] || [ "X$SKIP_CHECK_FILE" = "Xyes" ]; then
        if [ "$1" = "echo" ]; then
          echo "    -- $FILE"
        elif [ "$1" = "add" ]; then
          echo "  <localfile>" >> $NEWCONFIG
          if [ "$FILE" = "snort" ]; then
            head -n 1 $FILE|grep "\[**\] "|grep -v "Classification:" > /dev/null
            if [ $? = 0 ]; then
              echo "    <log_format>snort-full</log_format>" >> $NEWCONFIG
            else
              echo "    <log_format>snort-fast</log_format>" >> $NEWCONFIG
            fi
          else
            echo "    <log_format>$LOG_FORMAT</log_format>" >> $NEWCONFIG
          fi
          echo "    <location>$FILE</location>" >>$NEWCONFIG
          echo "  </localfile>" >> $NEWCONFIG
          echo "" >> $NEWCONFIG
        fi
      fi
  done
}

##########
# SetHeaders() 1-agent|manager|local
##########
SetHeaders()
{
    echo "########### JNote : running on inst-function.sh : SetHeaders() ###########"

    HEADERS_TMP="/tmp/wazuh-headers.tmp"
    if [ "$DIST_VER" = "0" ]; then
        sed -e "s/TYPE/$1/g; s/DISTRIBUTION/${DIST_NAME}/g; s/VERSION//g" "$HEADER_TEMPLATE" > $HEADERS_TMP
    else
      if [ "$DIST_SUBVER" = "0" ]; then
        sed -e "s/TYPE/$1/g; s/DISTRIBUTION/${DIST_NAME}/g; s/VERSION/${DIST_VER}/g" "$HEADER_TEMPLATE" > $HEADERS_TMP
      else
        sed -e "s/TYPE/$1/g; s/DISTRIBUTION/${DIST_NAME}/g; s/VERSION/${DIST_VER}.${DIST_SUBVER}/g" "$HEADER_TEMPLATE" > $HEADERS_TMP
      fi
    fi
    cat $HEADERS_TMP
    rm -f $HEADERS_TMP
}

##########
# WriteRootcheck()
##########
WriteRootcheck()
{
    echo "########### JNote : running on inst-function.sh : WriteRootcheck() ###########"

    # Adding to the config file
    if [ "X$ROOTCHECK" = "Xyes" ]; then
      ROOTCHECK_TEMPLATE=$(GetTemplate "rootcheck.$1.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
      if [ "$ROOTCHECK_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
        ROOTCHECK_TEMPLATE=$(GetTemplate "rootcheck.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
      fi
      sed -e "s|\${INSTALLDIR}|$INSTALLDIR|g" "${ROOTCHECK_TEMPLATE}" >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    else
      echo "  <rootcheck>" >> $NEWCONFIG
      echo "    <disabled>yes</disabled>" >> $NEWCONFIG
      echo "  </rootcheck>" >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi
}

##########
# WriteAgent() $1="no_locafiles" or empty
##########
WriteAgent()
{
    echo "########### JNote : running on inst-function.sh : WriteAgent() ###########"

    NO_LOCALFILES=$1

    HEADERS=$(SetHeaders "Agent")
    echo "$HEADERS" > $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "<ossec_config>" >> $NEWCONFIG
    echo "  <client>" >> $NEWCONFIG
    echo "    <server>" >> $NEWCONFIG
    if [ "X${HNAME}" = "X" ]; then
      echo "      <address>$SERVER_IP</address>" >> $NEWCONFIG
    else
      echo "      <address>$HNAME</address>" >> $NEWCONFIG
    fi
    echo "      <port>1514</port>" >> $NEWCONFIG
    echo "      <protocol>tcp</protocol>" >> $NEWCONFIG
    echo "    </server>" >> $NEWCONFIG
    if [ "X${USER_AGENT_CONFIG_PROFILE}" != "X" ]; then
         PROFILE=${USER_AGENT_CONFIG_PROFILE}
         echo "    <config-profile>$PROFILE</config-profile>" >> $NEWCONFIG
    else
      if [ "$DIST_VER" = "0" ]; then
        echo "    <config-profile>$DIST_NAME</config-profile>" >> $NEWCONFIG
      else
        if [ "$DIST_SUBVER" = "0" ]; then
          echo "    <config-profile>$DIST_NAME, $DIST_NAME$DIST_VER</config-profile>" >> $NEWCONFIG
        else
          echo "    <config-profile>$DIST_NAME, $DIST_NAME$DIST_VER, $DIST_NAME$DIST_VER.$DIST_SUBVER</config-profile>" >> $NEWCONFIG
        fi
      fi
    fi
    echo "    <notify_time>10</notify_time>" >> $NEWCONFIG
    echo "    <time-reconnect>60</time-reconnect>" >> $NEWCONFIG
    echo "    <auto_restart>yes</auto_restart>" >> $NEWCONFIG
    echo "    <crypto_method>aes</crypto_method>" >> $NEWCONFIG
    echo "  </client>" >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "  <client_buffer>" >> $NEWCONFIG
    echo "    <!-- Agent buffer options -->" >> $NEWCONFIG
    echo "    <disabled>no</disabled>" >> $NEWCONFIG
    echo "    <queue_size>5000</queue_size>" >> $NEWCONFIG
    echo "    <events_per_second>500</events_per_second>" >> $NEWCONFIG
    echo "  </client_buffer>" >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Rootcheck
    WriteRootcheck "agent"

    # CIS-CAT configuration
    if [ "X$DIST_NAME" !=  "Xdarwin" ]; then
        WriteCISCAT "agent"
    fi

    # Write osquery
    WriteOsquery "agent"

    # Syscollector configuration
    WriteSyscollector "agent"

    # Configuration assessment configuration
    WriteConfigurationAssessment

    # Syscheck
    WriteSyscheck "agent"

    # Write the log files
    if [ "X${NO_LOCALFILES}" = "X" ]; then
      echo "  <!-- Log analysis -->" >> $NEWCONFIG
      WriteLogs "add"
    else
      echo "  <!-- Log analysis -->" >> $NEWCONFIG
    fi

    # Localfile commands
    LOCALFILE_COMMANDS_TEMPLATE=$(GetTemplate "localfile-commands.agent.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    if [ "$LOCALFILE_COMMANDS_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      LOCALFILE_COMMANDS_TEMPLATE=$(GetTemplate "localfile-commands.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    fi
    cat ${LOCALFILE_COMMANDS_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Localfile extra
    LOCALFILE_EXTRA_TEMPLATE=$(GetTemplate "localfile-extra.agent.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    if [ "$LOCALFILE_EXTRA_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      LOCALFILE_EXTRA_TEMPLATE=$(GetTemplate "localfile-extra.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    fi
    if [ ! "$LOCALFILE_EXTRA_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      cat ${LOCALFILE_EXTRA_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi

    echo "  <!-- Active response -->" >> $NEWCONFIG

    echo "  <active-response>" >> $NEWCONFIG
    if [ "X$ACTIVERESPONSE" = "Xyes" ]; then
        echo "    <disabled>no</disabled>" >> $NEWCONFIG
    else
        echo "    <disabled>yes</disabled>" >> $NEWCONFIG
    fi
    echo "    <ca_store>etc/wpk_root.pem</ca_store>" >> $NEWCONFIG

    if [ -n "$CA_STORE" ]
    then
        echo "    <ca_store>${CA_STORE}</ca_store>" >> $NEWCONFIG
    fi

    echo "    <ca_verification>yes</ca_verification>" >> $NEWCONFIG
    echo "  </active-response>" >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Logging format
    cat ${LOGGING_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "</ossec_config>" >> $NEWCONFIG
}
##########
# WriteManager() $1="no_locafiles" or empty
##########
WriteManager()
{
    echo "########### JNote : running on inst-function.sh : WriteManager() ###########"

    NO_LOCALFILES=$1

    HEADERS=$(SetHeaders "Manager")
    echo "$HEADERS" > $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "<ossec_config>" >> $NEWCONFIG

    if [ "$EMAILNOTIFY" = "yes"   ]; then
        sed -e "s|<email_notification>no</email_notification>|<email_notification>yes</email_notification>|g; \
        s|<smtp_server>smtp.example.wazuh.com</smtp_server>|<smtp_server>${SMTP}</smtp_server>|g; \
        s|<email_from>wazuh@example.wazuh.com</email_from>|<email_from>wazuh@${HOST}</email_from>|g; \
        s|<email_to>recipient@example.wazuh.com</email_to>|<email_to>${EMAIL}</email_to>|g;" "${GLOBAL_TEMPLATE}" >> $NEWCONFIG
    else
        cat ${GLOBAL_TEMPLATE} >> $NEWCONFIG
    fi
    echo "" >> $NEWCONFIG

    # Alerts level
    cat ${ALERTS_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Logging format
    cat ${LOGGING_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Remote connection secure
    if [ "X$SLOG" = "Xyes" ]; then
      cat ${REMOTE_SEC_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi

    # Write rootcheck
    WriteRootcheck "manager"

    # CIS-CAT configuration
    if [ "X$DIST_NAME" !=  "Xdarwin" ]; then
        WriteCISCAT "manager"
    fi

    # Write osquery
    WriteOsquery "manager"

    # Syscollector configuration
    WriteSyscollector "manager"

    # Configuration assessment
    WriteConfigurationAssessment

    # Vulnerability Detector
    cat ${VULN_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Write syscheck
    WriteSyscheck "manager"

    # Active response
    if [ "$SET_WHITE_LIST"="true" ]; then
       sed -e "/  <\/global>/d" "${GLOBAL_AR_TEMPLATE}" >> $NEWCONFIG
      # Nameservers in /etc/resolv.conf
      for ip in ${NAMESERVERS} ${NAMESERVERS2};
        do
          if [ ! "X${ip}" = "X" -a ! "${ip}" = "0.0.0.0" ]; then
              echo "    <white_list>${ip}</white_list>" >>$NEWCONFIG
          fi
      done
      # Read string
      for ip in ${IPS};
        do
          if [ ! "X${ip}" = "X" -a ! "${ip}" = "0.0.0.0" ]; then
            echo $ip | grep -E "^[0-9./]{5,20}$" > /dev/null 2>&1
            if [ $? = 0 ]; then
              echo "    <white_list>${ip}</white_list>" >>$NEWCONFIG
            fi
          fi
        done
        echo "  </global>" >> $NEWCONFIG
        echo "" >> $NEWCONFIG
    else
      cat ${GLOBAL_AR_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi

    cat ${AR_COMMANDS_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG
    cat ${AR_DEFINITIONS_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Write the log files
    if [ "X${NO_LOCALFILES}" = "X" ]; then
      echo "  <!-- Log analysis -->" >> $NEWCONFIG
      WriteLogs "add"
    else
      echo "  <!-- Log analysis -->" >> $NEWCONFIG
    fi

    # Localfile commands
    LOCALFILE_COMMANDS_TEMPLATE=$(GetTemplate "localfile-commands.manager.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    if [ "$LOCALFILE_COMMANDS_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      LOCALFILE_COMMANDS_TEMPLATE=$(GetTemplate "localfile-commands.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    fi
    cat ${LOCALFILE_COMMANDS_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Localfile extra
    LOCALFILE_EXTRA_TEMPLATE=$(GetTemplate "localfile-extra.manager.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    if [ "$LOCALFILE_EXTRA_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      LOCALFILE_EXTRA_TEMPLATE=$(GetTemplate "localfile-extra.template" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    fi
    if [ ! "$LOCALFILE_EXTRA_TEMPLATE" = "ERROR_NOT_FOUND" ]; then
      cat ${LOCALFILE_EXTRA_TEMPLATE} >> $NEWCONFIG
      echo "" >> $NEWCONFIG
    fi
    

    # Writting rules configuration
    cat ${RULES_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Writting wazuh-logtest configuration
    cat ${RULE_TEST_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    # Writting auth configuration
    if [ "X${AUTHD}" = "Xyes" ]; then
        sed -e "s|\${INSTALLDIR}|$INSTALLDIR|g" "${AUTH_TEMPLATE}" >> $NEWCONFIG
        echo "" >> $NEWCONFIG
    else
        DisableAuthd
    fi

    # Writting cluster configuration
    cat ${CLUSTER_TEMPLATE} >> $NEWCONFIG
    echo "" >> $NEWCONFIG

    echo "</ossec_config>" >> $NEWCONFIG

}


InstallCommon()
{
    echo "########### JNote : running on inst-function.sh : InstallCommon() ###########"

    # ************ Line:706-719 ************
    WAZUH_GROUP='wazuh'
    WAZUH_USER='wazuh'
    INSTALL="install"

    if [ ${INSTYPE} = 'server' ]; then
        OSSEC_CONTROL_SRC='./init/wazuh-server.sh'
        OSSEC_CONF_SRC='../etc/ossec-server.conf'
    elif [ ${INSTYPE} = 'agent' ]; then
        OSSEC_CONTROL_SRC='./init/wazuh-client.sh'
        OSSEC_CONF_SRC='../etc/ossec-agent.conf'
    elif [ ${INSTYPE} = 'local' ]; then
        OSSEC_CONTROL_SRC='./init/wazuh-local.sh'
        OSSEC_CONF_SRC='../etc/ossec-local.conf'
    fi


    # ************ Line:866 ************
    ${INSTALL} -m 0750 -o root -g 0 ${OSSEC_CONTROL_SRC} ${INSTALLDIR}/bin/wazuh-control


    # ************ Line:914-928 ************
    if [ ! -f ${INSTALLDIR}/etc/client.keys ]; then
        if [ ${INSTYPE} = 'agent' ]; then
            ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/etc/client.keys
        else
            ${INSTALL} -m 0640 -o wazuh -g ${WAZUH_GROUP} /dev/null ${INSTALLDIR}/etc/client.keys
        fi
    fi

    if [ ! -f ${INSTALLDIR}/etc/ossec.conf ]; then
        if [ -f  ../etc/ossec.mc ]; then
            ${INSTALL} -m 0660 -o root -g ${WAZUH_GROUP} ../etc/ossec.mc ${INSTALLDIR}/etc/ossec.conf
        else
            ${INSTALL} -m 0660 -o root -g ${WAZUH_GROUP} ${OSSEC_CONF_SRC} ${INSTALLDIR}/etc/ossec.conf
        fi
    fi    

}

##########
# InstallSecurityConfigurationAssessmentFiles()
##########
InstallSecurityConfigurationAssessmentFiles()
{
    echo "########### JNote : running on inst-function.sh : InstallSecurityConfigurationAssessmentFiles() ###########"

    cd ..

    CONFIGURATION_ASSESSMENT_FILES_PATH=$(GetTemplate "sca.files" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})

    if [ "X$1" = "Xmanager" ]; then
        CONFIGURATION_ASSESSMENT_MANAGER_FILES_PATH=$(GetTemplate "sca.$1.files" ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER})
    fi
    cd ./src
    if [ "$CONFIGURATION_ASSESSMENT_FILES_PATH" = "ERROR_NOT_FOUND" ]; then
        echo "SCA policies are not available for this OS version ${DIST_NAME} ${DIST_VER} ${DIST_SUBVER}."
    else
        echo "Removing old SCA policies..."
        rm -f ${INSTALLDIR}/ruleset/sca/*

        echo "Installing SCA policies..."
        CONFIGURATION_ASSESSMENT_FILES=$(cat .$CONFIGURATION_ASSESSMENT_FILES_PATH)
        for FILE in $CONFIGURATION_ASSESSMENT_FILES; do
            if [ -f "../ruleset/sca/$FILE" ]; then
                ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} ../ruleset/sca/$FILE ${INSTALLDIR}/ruleset/sca
            else
                echo "ERROR: SCA policy not found: ../ruleset/sca/$FILE"
            fi
        done
    fi

    if [ "X$1" = "Xmanager" ]; then
        echo "Installing additional SCA policies..."
        CONFIGURATION_ASSESSMENT_FILES=$(cat .$CONFIGURATION_ASSESSMENT_MANAGER_FILES_PATH)
        for FILE in $CONFIGURATION_ASSESSMENT_FILES; do
            FILENAME=$(basename $FILE)
            if [ -f "../ruleset/sca/$FILE" ] && [ ! -f "${INSTALLDIR}/ruleset/sca/$FILENAME" ]; then
                ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} ../ruleset/sca/$FILE ${INSTALLDIR}/ruleset/sca/
                mv ${INSTALLDIR}/ruleset/sca/$FILENAME ${INSTALLDIR}/ruleset/sca/$FILENAME.disabled
            fi
        done
    fi
}

InstallLocal()
{
    echo "########### JNote : running on inst-function.sh : InstallLocal() ###########"

    InstallCommon

}

##########
# GenerateAuthCert()
##########
GenerateAuthCert()
{
    echo "########### JNote : running on inst-function.sh : GenerateAuthCert() ###########"

    if [ "X$SSL_CERT" = "Xyes" ]; then
        # Generation auto-signed certificate if not exists
        if [ ! -f "${INSTALLDIR}/etc/sslmanager.key" ] && [ ! -f "${INSTALLDIR}/etc/sslmanager.cert" ]; then
            if [ ! "X${USER_GENERATE_AUTHD_CERT}" = "Xn" ]; then
                if type openssl >/dev/null 2>&1; then
                    echo "Generating self-signed certificate for wazuh-authd..."
                    openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 -subj "/C=US/ST=California/CN=Wazuh/" -keyout ${INSTALLDIR}/etc/sslmanager.key -out ${INSTALLDIR}/etc/sslmanager.cert 2>/dev/null
                    chmod 640 ${INSTALLDIR}/etc/sslmanager.key
                    chmod 640 ${INSTALLDIR}/etc/sslmanager.cert
                else
                    echo "ERROR: OpenSSL not found. Cannot generate certificate for wazuh-authd."
                fi
            fi
        fi
    fi
}


InstallServer()
{
    echo "########### JNote : running on inst-function.sh : InstallServer() ###########"

    InstallLocal

    ${INSTALL} -m 0750 -o root -g 0 wazuh-authd ${INSTALLDIR}/bin

    GenerateAuthCert

}

InstallAgent()
{
    echo "########### JNote : running on inst-function.sh : InstallAgent() ###########"

    InstallCommon

    # InstallSecurityConfigurationAssessmentFiles "agent"

    # ************ Line:1171 ************
    ${INSTALL} -m 0750 -o root -g 0 agent-auth ${INSTALLDIR}/bin
}

InstallWazuh()
{
    echo "########### JNote : running on inst-function.sh : InstallWazuh() ###########"

    if [ "X$INSTYPE" = "Xagent" ]; then
        InstallAgent
    elif [ "X$INSTYPE" = "Xserver" ]; then
        InstallServer
    elif [ "X$INSTYPE" = "Xlocal" ]; then
        InstallLocal
    fi
}


##########
# GenerateService() $1=template
##########
GenerateService()
{
    echo "########### JNote : running on inst-function.sh : GenerateService() ###########"

    SERVICE_TEMPLATE=./src/init/templates/${1}
    sed "s|WAZUH_HOME_TMP|${INSTALLDIR}|g" ${SERVICE_TEMPLATE}
}