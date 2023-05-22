# 5/22(一) 針對 Ubuntu Wazuh-Agent/Server 的 os_auth 功能 的 install shell 重擬初版。


### Looking up for the execution directory
cd `dirname $0`

# ************ Line:771-785 ************ main function
##########
# main()
##########
main()
{
    LG="en"
    LANGUAGE="en"
    # Note : dist-detect.sh主要是在讀取系統資料
    . ./src/init/dist-detect.sh
    # Note : shared.sh 設定一些使用者名稱，以及ossec的路徑
    . ./src/init/shared.sh
    # Note : functions.sh 設定一個查詢有沒有這個資料夾的shell，沒什麼
    . ./src/init/functions.sh

    # Reading pre-defined file
    if [ ! `isFile ${PREDEF_FILE}` = "${FALSE}" ]; then
        . ${PREDEF_FILE}
    fi

    # 這邊省略了選語言的過程，直接使用英文

# ************ Line:827-832 ************ 
    . ./src/init/language.sh
    . ./src/init/init.sh
    . ./src/init/wazuh/wazuh.sh
    # Note : 這邊我拉了一個英文版本語言用的資料夾過來(extracted-wazuh-4.4.1/etc/templates/en/)
    # 這個檔案定義了一些安裝時的預設系統問句，供之後呼叫用。
    . ${TEMPLATE}/${LANGUAGE}/messages.txt 
    . ./src/init/inst-functions.sh
    . ./src/init/template-select.sh

    









}