DIR="/home/jerryhung/Desktop/"
GROUP="test"
USER="test"

sys_acct_chk () {
    $1 --help 2>&1 | grep -e " *-r.*system account" >/dev/null 2>&1 && echo "$1 -r" || echo "$1"
}
GROUPADD=$(sys_acct_chk "/usr/sbin/groupadd -f")
USERADD=$(sys_acct_chk "/usr/sbin/useradd")
    OSMYSHELL="/sbin/nologin"

if ! grep "^${GROUP}:" /etc/group > /dev/null 2>&1; then
    ${GROUPADD} "${GROUP}"
fi

if [ "${OSMYSHELL}" = "/sbin/nologin" ]; then
    # We first check if /sbin/nologin is present. If it is not,
    # we look for /bin/false. If none of them is present, we
    # just stick with nologin (no need to fail the install for that).
    if [ ! -f ${OSMYSHELL} ]; then
        if [ -f /bin/false ]; then
            OSMYSHELL="/bin/false"
        fi
    fi
 fi

if ! grep "^${USER}:" /etc/passwd > /dev/null 2>&1; then
    ${USERADD} "${USER}" -d "${DIR}" -s ${OSMYSHELL} -g "${GROUP}"
fi
