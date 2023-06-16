

<ossec_config>




  <rootcheck>
    <disabled>yes</disabled>
  </rootcheck>






  <syscheck>
    <disabled>yes</disabled>

    <scan_on_start>yes</scan_on_start>

    <!-- Generate alert when new file detected -->
    <alert_new_files>yes</alert_new_files>

  </syscheck>

    <white_list>127.0.0.53</white_list>
  </global>



  <!-- Log analysis -->



  <!-- Configuration for wazuh-authd -->
  <auth>
    <disabled>yes</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>


</ossec_config>
