# 5/22(一) 針對Ubuntu Wazuh-Agent/Server 的os_auth功能 的 makefile重擬初版。

# ************ Line:12-16 ************ uname_S 相關的設定
# libstdc++_path,LIBSTDCPP_NAME,libgcc_s_path,LIBGCC_S_NAME
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
uname_P := $(shell sh -c 'uname -p 2>/dev/null || echo not')
uname_R := $(shell sh -c 'uname -r 2>/dev/null || echo not')
uname_V := $(shell sh -c 'uname -v 2>/dev/null || echo not')
uname_M := $(shell sh -c 'uname -m 2>/dev/null || echo not')

ifeq (${TARGET}, winagent)
WAZUH_LIB_OUTPUT_PATH := win32/
STRIP_TOOL := i686-w64-mingw32-strip
libstdc++_path := $(shell sh -c 'i686-w64-mingw32-g++-posix --print-file-name=libstdc++-6.dll 2>/dev/null || echo not')
LIBSTDCPP_NAME := libstdc++-6.dll
libgcc_s_path := $(shell sh -c 'i686-w64-mingw32-g++-posix --print-file-name=libgcc_s_dw2-1.dll 2>/dev/null || echo not')
LIBGCC_S_NAME := libgcc_s_dw2-1.dll
else
libstdc++_path := $(shell sh -c 'g++ --print-file-name=libstdc++.so.6 2>/dev/null || echo not')
libgcc_s_path := $(shell sh -c 'g++ --print-file-name=libgcc_s.so.1 2>/dev/null || echo not')
LIBSTDCPP_NAME := libstdc++.so.6
LIBGCC_S_NAME := libgcc_s.so.1
STRIP_TOOL := strip
endif

# ************ Line:33-37 ************ uname_S 相關的設定
ifeq (, $(filter ${libstdc++_path}, not ${LIBSTDCPP_NAME}))
	ifeq (, $(filter ${libgcc_s_path}, not ${LIBGCC_S_NAME}))
	CPPLIBDEPS := ${LIBSTDCPP_NAME} ${LIBGCC_S_NAME}
	endif
endif

# ************ Line:39-45 ************ HAS_CHECKMODULE,HAS_SEMODULE_PACKAGE,CHECK_ARCHLINUX,CHECK_CENTOS5,CHECK_ALPINE,ARCH_FLAGS 相關的設定
HAS_CHECKMODULE = $(shell command -v checkmodule > /dev/null && echo YES)
HAS_SEMODULE_PACKAGE = $(shell command -v semodule_package > /dev/null && echo YES)
CHECK_ARCHLINUX := $(shell sh -c 'grep "Arch Linux" /etc/os-release > /dev/null && echo YES || echo not')
CHECK_CENTOS5 := $(shell sh -c 'grep "CentOS release 5." /etc/redhat-release 2>&1 > /dev/null && echo YES || echo not')
CHECK_ALPINE := $(shell sh -c 'grep "Alpine Linux" /etc/os-release 2>&1 > /dev/null && echo YES || echo not')

ARCH_FLAGS =

# ************ Line:48 ************ EXTERNAL_JSON 相關的設定
EXTERNAL_JSON=external/cJSON/

# ************ Line:51-53 ************ EXTERNAL_OPENSSL,EXTERNAL_LIBYAML 相關的設定
EXTERNAL_OPENSSL=external/openssl/
EXTERNAL_LIBYAML=external/libyaml/
EXTERNAL_CURL=external/curl/

# ************ Line:54 ************ EXTERNAL_AUDIT 相關的設定
EXTERNAL_AUDIT=external/audit-userspace/

# ************ Line:58-59 ************ EXTERNAL_MSGPACK,EXTERNAL_BZIP2 相關的設定
EXTERNAL_MSGPACK=external/msgpack/
EXTERNAL_BZIP2=external/bzip2/

# ************ Line:61 ************ EXTERNAL_LIBPCRE2 相關的設定
EXTERNAL_LIBPCRE2=external/libpcre2/

# ************ Line:62-67 ************ EXTERNAL_LIBDB,EXTERNAL_PACMAN,EXTERNAL_LIBARCHIVE 相關的設定
ifneq (${TARGET},winagent)
EXTERNAL_PROCPS=external/procps/
EXTERNAL_LIBDB=external/libdb/build_unix/
EXTERNAL_PACMAN=external/pacman/
EXTERNAL_LIBARCHIVE=external/libarchive/
endif

# ************ Line:69-72 ************ uname_S,EXTERNAL_RPM 相關的設定
ifeq (${uname_S},Linux)
EXTERNAL_RPM=external/rpm/
EXTERNAL_POPT=external/popt/
endif

# ************ Line:77-79 ************ WAZUH_GROUP,WAZUH_USER,SHARED 相關的設定
WAZUH_GROUP?=wazuh
WAZUH_USER?=wazuh
SHARED=so


# ************ Line:82-85 ************ SELINUX_MODULE,SELINUX_ENFORCEMENT,SELINUX_POLICY,SHARED_MODULES,RSYNC,DBSYNC 相關的設定
SELINUX_MODULE=selinux/wazuh.mod
SELINUX_ENFORCEMENT=selinux/wazuh.te
SELINUX_POLICY=selinux/wazuh.pp
SHARED_MODULES=shared_modules/
DBSYNC=${SHARED_MODULES}dbsync/
RSYNC=${SHARED_MODULES}rsync/

# ************ Line:87-88 ************ SYSCOLLECTOR,SYSINFO 相關的設定
SYSCOLLECTOR=wazuh_modules/syscollector/
SYSINFO=data_provider/


# ************ Line:95 ************ USE_AUDIT 相關的設定
USE_AUDIT=no

# ************ Line:123-128 ************ DEBUG 相關的設定
ifneq (,$(filter ${DEBUG},YES yes y Y 1))
SHARED_MODULES_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
GTEST_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
SYSCOLLECTOR_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
SYSINFO_RELEASE_TYPE=-DCMAKE_BUILD_TYPE=Debug
endif

# ************ Line:135-143 ************ USE_SELINUX 相關的設定
ifneq ($(HAS_CHECKMODULE),)
	ifneq ($(HAS_SEMODULE_PACKAGE),)
	USE_SELINUX=yes
	else
	USE_SELINUX=no
	endif
else
USE_SELINUX=no
endif

# ************ Line:148-150 ************ DEFINES 相關的設定
DEFINES=-DOSSECHIDS
DEFINES+=-DUSER=\"${WAZUH_USER}\"
DEFINES+=-DGROUPGLOBAL=\"${WAZUH_GROUP}\"

# ************ Line:152-181 ************ CC,OSSEC_CFLAGS 相關的設定
ifneq (${TARGET},winagent)
		DEFINES+=-D${uname_S}
ifeq (${uname_S},Linux)
		PRECOMPILED_OS:=linux
		DEFINES+=-DINOTIFY_ENABLED -D_XOPEN_SOURCE=600 -D_GNU_SOURCE
		ifeq (${CHECK_CENTOS5},YES)
				OSSEC_CFLAGS+=-pthread -I${EXTERNAL_LIBDB}
		else
				OSSEC_CFLAGS+=-pthread -I${EXTERNAL_LIBDB} -I${EXTERNAL_PACMAN}lib/libalpm/ -I${EXTERNAL_LIBARCHIVE}libarchive
		endif
		OSSEC_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../lib'
		AR_LDFLAGS+='-Wl,-rpath,$$ORIGIN/../../lib'
		ifeq (${CHECK_ALPINE},YES)
				OSSEC_LIBS+=-lintl
				DEFINES+=-DALPINE
		endif
		OSSEC_LIBS+=-lrt -ldl -lm
		OSSEC_LDFLAGS+=-pthread -lrt -ldl
		AR_LDFLAGS+=-pthread -lrt -ldl
		OSSEC_CFLAGS+=-Wl,--start-group
		USE_AUDIT=yes
		CC=gcc
		ifneq (,$(filter ${USE_AUDIT},YES yes y Y 1))
				OSSEC_CFLAGS+=-I$(EXTERNAL_AUDIT)lib
		endif
		ifeq (${CHECK_ARCHLINUX},YES)
				ARCH_FLAGS+=-lnghttp2 -lbrotlidec -lpsl
				OSSEC_LDFLAGS+=-lnghttp2 -lbrotlidec -lpsl
				AR_LDFLAGS+=-lnghttp2 -lbrotlidec -lpsl
		endif

# ************ Line:297-305 ************ OSSEC_CFLAGS 相關的設定
endif # Linux
else
		SHARED=dll
		DEFINES_EVENTCHANNEL=-D_WIN32_WINNT=0x600
		OSSEC_CFLAGS+=-pthread
		OSSEC_LDFLAGS+=-pthread
		AR_LDFLAGS+=-pthread
		PRECOMPILED_OS:=windows
endif # winagent


# ************ Line:329-334 ************ OSSEC_CFLAGS 相關的設定
ifneq (,$(filter ${DEBUG},YES yes y Y 1))
	OSSEC_CFLAGS+=-g
else
	OSSEC_CFLAGS+=-DNDEBUG
	OFLAGS+=-O2
endif #DEBUG

# ************ Line:336-337 ************ OSSEC_CFLAGS,OSSEC_LDFLAGS 相關的設定
OSSEC_CFLAGS+=${OFLAGS}
OSSEC_LDFLAGS+=${OFLAGS}

# ************ Line:343-349 ************ OSSEC_LDFLAGS 相關的設定
ifeq (${TARGET}, winagent)
	OSSEC_LDFLAGS+=-L${DBSYNC}build/bin
	OSSEC_LDFLAGS+=-L${RSYNC}build/bin
else
	OSSEC_LDFLAGS+=-L${DBSYNC}build/lib
	OSSEC_LDFLAGS+=-L${RSYNC}build/lib
endif


# ************ Line:367-372 ************ OSSEC_CFLAGS,OSSEC_LDFLAGS 相關的設定
OSSEC_CFLAGS+=${DEFINES}
OSSEC_CFLAGS+=-pipe -Wall -Wextra -std=gnu99
OSSEC_CFLAGS+=-I./ -I./headers/ -I${EXTERNAL_OPENSSL}include -I$(EXTERNAL_JSON) -I${EXTERNAL_LIBYAML}include -I${EXTERNAL_CURL}include -I${EXTERNAL_MSGPACK}include -I${EXTERNAL_BZIP2} -I${SHARED_MODULES}common -I${DBSYNC}include -I${RSYNC}include -I${SYSCOLLECTOR}include  -I${SYSINFO}include  -I${EXTERNAL_LIBPCRE2}include -I${EXTERNAL_RPM}/builddir/output/include

OSSEC_CFLAGS += ${CFLAGS}
OSSEC_LDFLAGS += ${LDFLAGS}


# ************ Line:374 ************ OSSEC_LIBS 相關的設定
OSSEC_LIBS += $(LIBS)

# ************ Line:376-381 ************ CCCOLOR,ENDCOLOR,SRCCOLOR 相關的設定
CCCOLOR="\033[34m"
LINKCOLOR="\033[34;1m"
SRCCOLOR="\033[33m"
BINCOLOR="\033[37;1m"
MAKECOLOR="\033[32;1m"
ENDCOLOR="\033[0m"

# ************ Line:383-391 ************ QUIET_CC,QUIET_CCBIN 相關的設定
ifeq (,$(filter ${V},YES yes y Y 1))
	QUIET_CC      = @printf '    %b %b\n' ${CCCOLOR}CC${ENDCOLOR} ${SRCCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_LINK    = @printf '    %b %b\n' ${LINKCOLOR}LINK${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_CCBIN   = @printf '    %b %b\n' ${LINKCOLOR}CC${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_INSTALL = @printf '    %b %b\n' ${LINKCOLOR}INSTALL${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_RANLIB  = @printf '    %b %b\n' ${LINKCOLOR}RANLIB${ENDCOLOR} ${BINCOLOR}$@${ENDCOLOR} 1>&2;
	QUIET_NOTICE  = @printf '%b' ${MAKECOLOR} 1>&2;
	QUIET_ENDCOLOR= @printf '%b' ${ENDCOLOR} 1>&2;
endif

# ************ Line:393-405 ************ MING_BASE, CC 相關的設定
MING_BASE:=
ifeq (${TARGET}, winagent)
# Avoid passing environment variables such CFLAGS to external Makefiles
ifeq (${CC}, gcc)
	MAKEOVERRIDES=
endif

CC=gcc
ifeq (${TARGET}, winagent)
CXX=g++-posix
else
CXX=g++
endif

# ************ Line:407-434 ************ MING_BASE,CC 相關的設定
ifneq (,$(shell which amd64-mingw32msvc-gcc))
	ifeq (${CC}, gcc)
		MING_BASE:=amd64-mingw32msvc-
	else
		MING_BASE:=
	endif
	MINGW_HOST="amd64-mingw32msvc"
else
ifneq (,$(shell which i686-pc-mingw32-gcc))
	ifeq (${CC}, gcc)
		MING_BASE:=i686-pc-mingw32-
	else
		MING_BASE:=
	endif
	MINGW_HOST="i686-pc-mingw32"
else
ifneq (,$(shell which i686-w64-mingw32-gcc))
	ifeq (${CC}, gcc)
		MING_BASE:=i686-w64-mingw32-
	else
		MING_BASE:=
	endif
	MINGW_HOST="i686-w64-mingw32"
else
$(error No windows cross-compiler found!) #MING_BASE:=unknown-
endif
endif
endif

endif #winagent

# ************ Line:446-447,449-450 ************ OSSEC_CC, OSSEC_CCBIN 相關的設定
OSSEC_CC      =${QUIET_CC}${MING_BASE}${CC}
OSSEC_CCBIN   =${QUIET_CCBIN}${MING_BASE}${CC}
OSSEC_LINK    =${QUIET_LINK}${MING_BASE}ar -crus
OSSEC_RANLIB  =${QUIET_RANLIB}${MING_BASE}ranlib

# ************ Line:454-461 ************ OSSEC_CFLAGS,OSSEC_LDFLAGS,OSSEC_LIBS 相關的設定
ifneq (,$(filter ${USE_INOTIFY},YES auto yes y Y 1))
	DEFINES+=-DINOTIFY_ENABLED
	ifeq (${uname_S},FreeBSD)
		OSSEC_LDFLAGS+=-L/usr/local/lib -I/usr/local/include
		OSSEC_LIBS+=-linotify
		OSSEC_CFLAGS+=-I/usr/local/include
	endif
endif

# ************ Line:467-472 ************ OSSEC_LDFLAGS,OSSEC_LIBS 相關的設定
ifneq (,$(filter ${USE_PRELUDE},YES auto yes y Y 1))
	DEFINES+=-DPRELUDE_OUTPUT_ENABLED
	OSSEC_LIBS+=-lprelude
	OSSEC_LDFLAGS+=$(shell sh -c '${PRELUDE_CONFIG} --pthread-cflags')
	OSSEC_LIBS+=$(shell sh -c '${PRELUDE_CONFIG} --libs')
endif # USE_PRELUDE

# ************ Line:474-482 ************ OSSEC_LIBS 相關的設定
ifneq (,$(filter ${USE_ZEROMQ},YES auto yes y Y 1))
	DEFINES+=-DZEROMQ_OUTPUT_ENABLED
	OSSEC_LIBS+=-lzmq -lczmq
endif # USE_ZEROMQ

ifneq (,$(filter ${USE_GEOIP},YES auto yes y Y 1))
	DEFINES+=-DLIBGEOIP_ENABLED
	OSSEC_LIBS+=-lGeoIP
endif # USE_GEOIP


# ************ Line:486-492 ************ OSSEC_LDFLAGS 相關的設定
ifeq (${TARGET}, winagent)
	OSSEC_LDFLAGS+=-L${SYSCOLLECTOR}build/bin
	OSSEC_LDFLAGS+=-L${SYSINFO}build/bin
else
	OSSEC_LDFLAGS+=-L${SYSCOLLECTOR}build/lib
	OSSEC_LDFLAGS+=-L${SYSINFO}build/lib
endif


# ************ Line:498-571 ************ 有關 Database 的 OSSEC_LIBS 相關的設定
MI :=
PI :=
ifdef DATABASE

	ifeq (${DATABASE},mysql)
		DEFINES+=-DMYSQL_DATABASE_ENABLED

		ifdef MYSQL_CFLAGS
			MI = ${MYSQL_CFLAGS}
		else
			MI := $(shell sh -c '${MY_CONFIG} --include 2>/dev/null || echo ')

			ifeq (${MI},) # BEGIN MI manual detection
				ifneq (,$(wildcard /usr/include/mysql/mysql.h))
					MI="-I/usr/include/mysql/"
				else
					ifneq (,$(wildcard /usr/local/include/mysql/mysql.h))
						MI="-I/usr/local/include/mysql/"
					endif  #
				endif  #MI

			endif
		endif # MYSQL_CFLAGS

		ifdef MYSQL_LIBS
			ML = ${MYSQL_LIBS}
		else
			ML := $(shell sh -c '${MY_CONFIG} --libs 2>/dev/null || echo ')

			ifeq (${ML},)
				ifneq (,$(wildcard /usr/lib/mysql/*))
					ML="-L/usr/lib/mysql"
				else
					ifneq (,$(wildcard /usr/lib64/mysql/*))
						ML="-L/usr/lib64/mysql"
					else
						ifneq (,$(wildcard /usr/local/lib/mysql/*))
							ML="-L/usr/local/lib/mysql"
						else
							ifneq (,$(wildcard /usr/local/lib64/mysql/*))
								ML="-L/usr/local/lib64/mysql"
							endif # local/lib64
						endif # local/lib
					endif # lib54
				endif # lib
			endif
		endif # MYSQL_LIBS

		OSSEC_LIBS+=${ML} -lmysqlclient

	else # DATABASE

		ifeq (${DATABASE}, pgsql)
			DEFINES+=-DPGSQL_DATABASE_ENABLED

			ifneq (${PGSQL_LIBS},)
				PL:=${PGSQL_LIBS}
			else
				PL:=$(shell sh -c '(${PG_CONFIG} --libdir --pkglibdir 2>/dev/null | sed "s/^/-L/g" | xargs ) || echo ')
			endif

			ifneq (${PGSQL_CFLAGS},)
				PI:=${PGSQL_CFLAGS}
			else
				PI:=$(shell sh -c '(${PG_CONFIG} --includedir --pkgincludedir 2>/dev/null | sed "s/^/-I/g" | xargs ) || echo ')
			endif

			# XXX need some basic autodetech stuff here.

			OSSEC_LIBS+=${PL} -lpq

		endif # pgsql
	endif # mysql
endif # DATABASE


# ************ Line:573-609 ************ Target
####################
#### Target ########
####################

ifndef TARGET
	TARGET=failtarget
endif # TARGET

ifeq (${TARGET},agent)
	DEFINES+=-DCLIENT
endif

ifeq (${TARGET},local)
	DEFINES+=-DLOCAL
endif

.PHONY: build
build: ${TARGET}
ifneq (${TARGET},failtarget)
	${MAKE} settings
	@echo
	${QUIET_NOTICE}
	@echo "Done building ${TARGET}"
	${QUIET_ENDCOLOR}
endif
	@echo

.PHONY: failtarget
failtarget:
	@echo "TARGET is required: "
	@echo "   make TARGET=server   to build the server"
	@echo "   make TARGET=local      - local version of server"
	@echo "   make TARGET=hybrid     - hybrid version of server"
	@echo "   make TARGET=agent    to build the unix agent"
	@echo "   make TARGET=winagent to build the windows agent"

# ************ Line:655-697 ************ 有關 Setting 的設定
.PHONY: settings
settings:
	@echo
	@echo "General settings:"
	@echo "    TARGET:             ${TARGET}"
	@echo "    V:                  ${V}"
	@echo "    DEBUG:              ${DEBUG}"
	@echo "    DEBUGAD             ${DEBUGAD}"
	@echo "    INSTALLDIR:         ${INSTALLDIR}"
	@echo "    DATABASE:           ${DATABASE}"
	@echo "    ONEWAY:             ${ONEWAY}"
	@echo "    CLEANFULL:          ${CLEANFULL}"
	@echo "    RESOURCES_URL:      ${RESOURCES_URL}"
	@echo "    EXTERNAL_SRC_ONLY:  ${EXTERNAL_SRC_ONLY}"
	@echo "User settings:"
	@echo "    WAZUH_GROUP:        ${WAZUH_GROUP}"
	@echo "    WAZUH_USER:         ${WAZUH_USER}"
	@echo "USE settings:"
	@echo "    USE_ZEROMQ:         ${USE_ZEROMQ}"
	@echo "    USE_GEOIP:          ${USE_GEOIP}"
	@echo "    USE_PRELUDE:        ${USE_PRELUDE}"
	@echo "    USE_INOTIFY:        ${USE_INOTIFY}"
	@echo "    USE_BIG_ENDIAN:     ${USE_BIG_ENDIAN}"
	@echo "    USE_SELINUX:        ${USE_SELINUX}"
	@echo "    USE_AUDIT:          ${USE_AUDIT}"
	@echo "    DISABLE_SYSC:       ${DISABLE_SYSC}"
	@echo "    DISABLE_CISCAT:     ${DISABLE_CISCAT}"
	@echo "    IMAGE_TRUST_CHECKS: ${IMAGE_TRUST_CHECKS}"
	@echo "    CA_NAME:            ${CA_NAME}"
	@echo "Mysql settings:"
	@echo "    includes:           ${MI}"
	@echo "    libs:               ${ML}"
	@echo "Pgsql settings:"
	@echo "    includes:           ${PI}"
	@echo "    libs:               ${PL}"
	@echo "Defines:"
	@echo "    ${DEFINES}"
	@echo "Compiler:"
	@echo "    CFLAGS            ${OSSEC_CFLAGS}"
	@echo "    LDFLAGS           ${OSSEC_LDFLAGS}"
	@echo "    LIBS              ${OSSEC_LIBS}"
	@echo "    CC                ${CC}"
	@echo "    MAKE              ${MAKE}"

# ************ Line:712 ************ BUILD_SERVER : auth 相關的部分
BUILD_SERVER+=wazuh-authd


# ************ Line:721 ************ BUILD_AGENT : auth 相關的部分
BUILD_AGENT+=agent-auth


# ************ Line:729-733 ************ BUILD_CMAKE_PROJECTS 相關的設定
#BUILD_CMAKE_PROJECTS+=build_sysinfo
#BUILD_CMAKE_PROJECTS+=build_shared_modules
#ifeq (,$(filter ${DISABLE_SYSC},YES yes y Y 1))
#BUILD_CMAKE_PROJECTS+=build_syscollector
#endif

# ************ Line:735-741 ************ 還不知道要不要留
${WAZUH_LIB_OUTPUT_PATH}${LIBSTDCPP_NAME}: ${libstdc++_path}
	cp $< $@
	${STRIP_TOOL} -x $@

${WAZUH_LIB_OUTPUT_PATH}${LIBGCC_S_NAME}: ${libgcc_s_path}
	cp $< $@
	${STRIP_TOOL} -x $@


# ************ Line:743-789 ************ make agent/server 相關
.PHONY: server agent # JNote : 被註解掉的 : local hybrid selinux

ifeq (${MAKECMDGOALS},server)
$(error Do not use 'server' directly, use 'TARGET=server')
endif

#server: external ${CPPLIBDEPS}
#	${MAKE} ${BUILD_SERVER} ${BUILD_CMAKE_PROJECTS}

# JNote : 原始的是上面那行，但BUILD_CMAKE_PROJECTS被註解掉了
server: external ${CPPLIBDEPS}
	${MAKE} ${BUILD_SERVER}

ifeq (${MAKECMDGOALS},agent)
$(error Do not use 'agent' directly, use 'TARGET=agent')
endif
agent: external ${CPPLIBDEPS}

# JNote : 這邊被我註解調，不要build cmake 的project
#ifneq (${uname_S},HP-UX)
#	${MAKE} ${BUILD_CMAKE_PROJECTS}
#
#endif
	${MAKE} ${BUILD_AGENT}

ifneq (,$(filter ${USE_SELINUX},YES yes y Y 1))
server local hybrid agent: selinux
endif

selinux: $(SELINUX_POLICY)

$(SELINUX_POLICY): $(SELINUX_MODULE)
	semodule_package -o $@ -m $?

$(SELINUX_MODULE): $(SELINUX_ENFORCEMENT)
	checkmodule -M -m -o $@ $?

WINDOWS_BINS:=win32/wazuh-agent.exe win32/wazuh-agent-eventchannel.exe win32/manage_agents.exe win32/setup-windows.exe win32/setup-syscheck.exe win32/setup-iis.exe win32/os_win32ui.exe win32/agent-auth.exe win32/syscollector
WINDOWS_ACTIVE_RESPONSES:=win32/restart-wazuh.exe win32/route-null.exe win32/netsh.exe

ifeq (${MAKECMDGOALS},winagent)
$(error Do not use 'winagent' directly, use 'TARGET=winagent')
endif


# ************ Line:953-968 ************
#### zlib ##########

$(ZLIB_LIB):
ifeq (${TARGET},winagent)
	cd ${EXTERNAL_ZLIB} && cp zconf.h.in zconf.h && ${MAKE} -f win32/Makefile.gcc PREFIX=${MING_BASE} libz.a
else
	cd ${EXTERNAL_ZLIB} && CFLAGS=-fPIC ./configure && ${MAKE} libz.a
endif

ZLIB_INCLUDE=-I./${EXTERNAL_ZLIB}

os_zlib_c := os_zlib/os_zlib.c
os_zlib_o := $(os_zlib_c:.c=.o)

os_zlib/%.o: os_zlib/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $< -o $@

# ************ Line:1183-1248 ************
################################
#### External dependencies  ####
################################

TAR := tar -xf
GUNZIP := gunzip
GZIP := gzip
CURL := curl -so
DEPS_VERSION = 20
RESOURCES_URL := https://packages.wazuh.com/deps/$(DEPS_VERSION)
CPYTHON := cpython
PYTHON_SOURCE := no

ifneq (${TARGET}, winagent)
	ifneq (,$(filter ${uname_S},Linux Darwin HP-UX))
		cpu_arch := ${uname_M}
		ifneq (,$(filter ${cpu_arch},x86_64 amd64))
			PRECOMPILED_ARCH := /amd64
		else
		ifneq (,$(filter ${cpu_arch},i386 i686))
			PRECOMPILED_ARCH := /i386
		else
		ifneq (,$(filter ${cpu_arch},aarch64 arm64))
			PRECOMPILED_ARCH := /aarch64
		else
		ifneq (,$(filter ${cpu_arch},armv8l armv7l arm32 armhf))
			PRECOMPILED_ARCH := /arm32
		else
		ifeq (${cpu_arch},ppc64le)
			PRECOMPILED_ARCH := /ppc64le
		else
		ifneq (,$(filter ${cpu_arch},ia64))
			PRECOMPILED_ARCH := /ia64
		else
			PRECOMPILED_ARCH := /${uname_P}
		endif
		endif
		endif
		endif
		endif
		endif
	else
	ifneq (,$(filter ${uname_S},SunOS AIX))
		cpu_arch := ${uname_P}
		ifeq (${cpu_arch},powerpc)
			PRECOMPILED_ARCH := /powerpc
		else
		ifneq (,$(filter ${cpu_arch},sparc sun4u))
			PRECOMPILED_ARCH := /sparc
		else
		ifneq (,$(filter ${cpu_arch},i386 i86pc))
			PRECOMPILED_ARCH := /i386
		else
			PRECOMPILED_ARCH := /${uname_M}
		endif
		endif
		endif
	else
    	cpu_arch := ${uname_M}

	ifneq (,$(filter ${cpu_arch},unknown Unknown not))
		cpu_arch := ${uname_P}
	endif
	PRECOMPILED_ARCH := /${cpu_arch}
	endif
	endif
endif

# ************ Line:1256-1270 ************
ifeq (,$(filter ${EXTERNAL_SRC_ONLY},YES yes y Y 1))
# If EXTERNAL_SRC_ONLY=YES is not defined, lets look for the precompiled lib
PRECOMPILED_RES := $(PRECOMPILED_OS)$(PRECOMPILED_ARCH)
endif

# Agent dependencies
# EXTERNAL_RES := cJSON curl libdb libffi libyaml openssl procps sqlite zlib audit-userspace msgpack bzip2 nlohmann googletest  libplist pacman libarchive popt rpm

# JNote : EXTERNAL_RES 不知道有沒有少
EXTERNAL_RES := cJSON curl openssl sqlite zlib libpcre2
ifneq (${TARGET},agent)
	ifneq (${TARGET},winagent)
		# Manager extra dependency
		EXTERNAL_RES += $(CPYTHON) jemalloc
	endif
endif
EXTERNAL_DIR := $(EXTERNAL_RES:%=external/%)
EXTERNAL_TAR := $(EXTERNAL_RES:%=external/%.tar.gz)

# ************ Line:1272-1323 ************
.PHONY: deps
deps: $(EXTERNAL_TAR)

external/$(CPYTHON).tar.gz:
# Python interpreter
ifeq (,$(filter ${PYTHON_SOURCE},YES yes y Y 1))
	ifneq (,$(PRECOMPILED_RES))
	external/$(CPYTHON).tar.gz: external-precompiled/$(CPYTHON).tar.gz
		test -e $(patsubst %.gz,%,$@) ||\
		($(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(patsubst external/%,%,$@) &&\
		cd external && $(GUNZIP) $(patsubst external/%,%,$@) && $(TAR) $(patsubst external/%.gz,%,$@) && rm $(patsubst external/%.gz,%,$@))
		test -d $(patsubst %.tar.gz,%,$@) || (cd external && $(GZIP) $(patsubst external/%.gz,%,$@))

	external-precompiled/$(CPYTHON).tar.gz:
		-$(CURL) external/$(patsubst external-precompiled/%,%,$@) $(RESOURCES_URL)/libraries/$(PRECOMPILED_RES)/$(patsubst external-precompiled/%,%,$@) || true
		-cd external && test -e $(patsubst external-precompiled/%,%,$@) && $(GUNZIP) $(patsubst external-precompiled/%,%,$@) || true
	else
	external/$(CPYTHON).tar.gz:
		$(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(patsubst external/%,%,$@)
		cd external && $(GUNZIP) $(patsubst external/%,%,$@)
		cd external && $(TAR) $(patsubst external/%.gz,%,$@)
		rm $(patsubst %.gz,%,$@)
	endif
else
	external/$(CPYTHON).tar.gz:
		$(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(patsubst external/%,%,$@)
		cd external && $(GUNZIP) $(patsubst external/%,%,$@)
		cd external && $(TAR) $(patsubst external/%.gz,%,$@)
		rm $(patsubst %.gz,%,$@)
endif

# Remaining dependencies
ifneq (,$(PRECOMPILED_RES))
external/%.tar.gz: external-precompiled/%.tar.gz
	test -d $(patsubst %.tar.gz,%,$@) ||\
	($(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(patsubst external/%,%,$@) &&\
	cd external && $(GUNZIP) $(patsubst external/%,%,$@) && $(TAR) $(patsubst external/%.gz,%,$@) && rm $(patsubst external/%.gz,%,$@))
else
external/%.tar.gz:
	$(CURL) $@ $(RESOURCES_URL)/libraries/sources/$(patsubst external/%,%,$@)
	cd external && $(GUNZIP) $(patsubst external/%,%,$@)
	cd external && $(TAR) $(patsubst external/%.gz,%,$@)
	rm $(patsubst %.gz,%,$@)
endif

ifneq (,$(PRECOMPILED_RES))
external-precompiled/%.tar.gz:
	-$(CURL) external/$(patsubst external-precompiled/%,%,$@) $(RESOURCES_URL)/libraries/$(PRECOMPILED_RES)/$(patsubst external-precompiled/%,%,$@) || true
	-cd external && test -e $(patsubst external-precompiled/%,%,$@) && $(GUNZIP) $(patsubst external-precompiled/%,%,$@) || true
	-cd external && test -e $(patsubst external-precompiled/%.gz,%,$@) && $(TAR) $(patsubst external-precompiled/%.gz,%,$@) || true
	-test -e external/$(patsubst external-precompiled/%.gz,%,$@) && rm external/$(patsubst external-precompiled/%.gz,%,$@) || true
endif


# ************ Line:1323-1333 ************
####################
#### OSSEC Libs ####
####################
WAZUHEXT_LIB = libwazuhext.$(SHARED)
WAZUH_LIB = libwazuhshared.$(SHARED)
BUILD_LIBS = libwazuh.a $(WAZUHEXT_LIB)

$(BUILD_SERVER) $(BUILD_AGENT) $(WINDOWS_BINS): $(BUILD_LIBS)


# ************ Line:1335-1357 ************
#### os_xml ########

os_xml_c := $(wildcard os_xml/*.c)
os_xml_o := $(os_xml_c:.c=.o)

os_xml/%.o: os_xml/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -c $^ -o $@

#### os_regex ######

os_regex_c := $(wildcard os_regex/*.c)
os_regex_o := $(os_regex_c:.c=.o)

os_regex/%.o: os_regex/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -c $^ -o $@

#### os_net ##########

os_net_c := $(wildcard os_net/*.c)
os_net_o := $(os_net_c:.c=.o)

os_net/%.o: os_net/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -c $^ -o $@


# ************ Line:1527-1537 ************
shared_c := $(wildcard shared/*.c)
shared_o := $(shared_c:.c=.o)

shared/%.o: shared/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -DARGV0=\"wazuh-remoted\" -c $^ -o $@

shared/debug_op_proc.o: shared/debug_op.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -DMA -DARGV0=\"wazuh-remoted\" -c $^ -o $@

shared/file_op_proc.o: shared/file_op.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -fPIC -DCLIENT -DARGV0=\"wazuh-remoted\" -c $^ -o $@


# ************ Line:1556-1562 ************
#### Config ##########

config_c := $(wildcard config/*.c)
config_o := $(config_c:.c=.o)

config/%.o: config/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@


# ************ Line:1583-1605 ************
#### Wazuh modules ##
wmodules_c := $(wildcard wazuh_modules/wm*.c) $(wildcard wazuh_modules/agent_upgrade/*.c)

ifeq (${TARGET},agent)
	wmodules_c := ${wmodules_c} $(wildcard wazuh_modules/agent_upgrade/agent/*.c)
else ifeq (${TARGET},winagent)
	wmodules_c := ${wmodules_c} $(wildcard wazuh_modules/agent_upgrade/agent/*.c)
else
	wmodules_c := ${wmodules_c} $(wildcard wazuh_modules/vulnerability_detector/*.c)
	wmodules_c := ${wmodules_c} $(wildcard wazuh_modules/task_manager/*.c)
	wmodules_c := ${wmodules_c} $(wildcard wazuh_modules/agent_upgrade/manager/*.c)
endif

wmodules_o := $(wmodules_c:.c=.o)

wazuh_modules/%.o: wazuh_modules/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

wmodules_dep := ${wmodules_o} ${wdblib_o}

ifeq (${uname_S},HP-UX)
	wmodules_dep := ${wmodules_dep} ${config_o}
endif

# ************ Line:1607-1689 ************
#### crypto ##########

crypto_blowfish_c := os_crypto/blowfish/bf_op.c
crypto_blowfish_o := $(crypto_blowfish_c:.c=.o)

os_crypto/blowfish/%.o: os_crypto/blowfish/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_md5_c := os_crypto/md5/md5_op.c
crypto_md5_o := $(crypto_md5_c:.c=.o)

os_crypto/md5/%.o: os_crypto/md5/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_sha1_c := os_crypto/sha1/sha1_op.c
crypto_sha1_o := $(crypto_sha1_c:.c=.o)

os_crypto/sha1/%.o: os_crypto/sha1/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_sha256_c := os_crypto/sha256/sha256_op.c
crypto_sha256_o := $(crypto_sha256_c:.c=.o)

os_crypto/sha256/%.o: os_crypto/sha256/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_sha512_c := os_crypto/sha512/sha512_op.c
crypto_sha512_o := $(crypto_sha512_c:.c=.o)

os_crypto/sha512/%.o: os_crypto/sha512/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_aes_c := os_crypto/aes/aes_op.c
crypto_aes_o := $(crypto_aes_c:.c=.o)

os_crypto/aes/%.o: os_crypto/aes/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_md5_sha1_c := os_crypto/md5_sha1/md5_sha1_op.c
crypto_md5_sha1_o := $(crypto_md5_sha1_c:.c=.o)

os_crypto/md5_sha1/%.o: os_crypto/md5_sha1/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_md5_sha1_sha256_c := os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.c
crypto_md5_sha1_sha256_o := $(crypto_md5_sha1_sha256_c:.c=.o)

os_crypto/md5_sha1_sha256/%.o: os_crypto/md5_sha1_sha256/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_hmac_c := os_crypto/hmac/hmac.c
crypto_hmac_o := $(crypto_hmac_c:.c=.o)

os_crypto/hmac/%.o: os_crypto/hmac/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $^ -o $@

crypto_shared_c := $(wildcard os_crypto/shared/*.c)
crypto_shared_o := $(crypto_shared_c:.c=.o)

os_crypto/shared/%.o: os_crypto/shared/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $< -o $@

crypto_signature_c := $(wildcard os_crypto/signature/*.c)
crypto_signature_o := $(crypto_signature_c:.c=.o)

os_crypto/signature/%.o: os_crypto/signature/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $< -o $@

analysisd/logmsg.o: analysisd/logmsg.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -c $< -o $@


crypto_o := ${crypto_blowfish_o} \
					 ${crypto_md5_o} \
					 ${crypto_sha1_o} \
					 ${crypto_shared_o} \
					 ${crypto_md5_sha1_o} \
					 ${crypto_md5_sha1_sha256_o} \
					 ${crypto_sha256_o} \
					 ${crypto_sha512_o} \
					 ${crypto_aes_o} \
					 ${crypto_hmac_o} \
					 ${crypto_signature_o}

# ************ Line:1691-1740 ************ libwazuh,libwazuhext 
#### libwazuh ######### JNote : 先刪掉了  ${UNIT_TEST_WRAPPERS}
libwazuh.a: ${config_o} ${wmodules_dep} ${crypto_o} ${shared_o} ${os_net_o} ${os_regex_o} ${os_xml_o} ${os_zlib_o} ${manage_agents} os_auth/ssl.o os_auth/check_cert.o addagent/validate.o analysisd/logmsg.o
	${OSSEC_LINK} $@ $^
	${OSSEC_RANLIB} $@

### libwazuhext #########

ifeq (${uname_S},Darwin)
WAZUH_SHFLAGS=-install_name @rpath/libwazuhext.$(SHARED)

$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) $(WAZUH_SHFLAGS) -o $@ -Wl,-all_load $^ -Wl,-noall_load $(OSSEC_LIBS)
else # JNote : 這邊會有用
ifeq (${TARGET}, winagent)
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ -static-libgcc -Wl,--export-all-symbols -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
else
ifeq (${uname_S},SunOS)
	ifneq ($(uname_R),5.10)
	LIBGCC_FLAGS := -static-libgcc
	else
	LIBGCC_FLAGS := -Wl,-rpath,\$$ORIGIN
	endif
	
	ifeq (${uname_P},sparc)
	$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
		$(OSSEC_SHARED) $(OSSEC_CFLAGS) -mimpure-text -o $@ $(LIBGCC_FLAGS) -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
	else
	$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
		$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ $(LIBGCC_FLAGS) -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
	endif
else
ifneq (,$(filter ${uname_S},AIX HP-UX))
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	mkdir -p libwazuhext;
	find external/ -name \*.a -exec cp {} libwazuhext/ \;
	for lib in libcjson.a libz.a libmsgpack.a libssl.a libcrypto.a libsqlite3.a libyaml.a libpcre2-8.a ; do \
		ar -x libwazuhext/$$lib; \
		mv *.o libwazuhext/; \
	done
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) libwazuhext/*.o -o $@ -static-libgcc

else # JNote : 應該會直接跑這邊
$(WAZUHEXT_LIB): $(EXTERNAL_LIBS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
endif
endif
endif
endif

# ************ Line:1836-1846 ************ addagent 的功能
#### addagent ######

addagent_c := $(wildcard addagent/*.c)
addagent_o := $(addagent_c:.c=.o)

addagent/%.o: addagent/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -I./addagent -DARGV0=\"manage_agents\" -c $^ -o $@


manage_agents: ${addagent_o}
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@


# ************ Line:1915-1951 ************ libwazuhshared
### libwazuhshared.so #########

ifeq (${uname_S},Darwin)
WAZUH_SHARED_SHFLAGS=-install_name @rpath/libwazuhshared.$(SHARED)

$(WAZUH_LIB): $(WAZUHEXT_LIB) $(AR_PROGRAMS_DEPS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) $(WAZUH_SHARED_SHFLAGS) -o $@ -Wl,-all_load $^ -Wl,-noall_load $(OSSEC_LIBS)
else # JNote : Windows 這邊會跑
ifeq (${TARGET}, winagent)
$(WAZUH_LIB): $(WAZUHEXT_LIB) $(AR_PROGRAMS_DEPS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -UOSSECHIDS -o $@ -static-libgcc -Wl,--export-all-symbols -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
else
ifeq (${uname_S},SunOS)
	ifneq ($(uname_R),5.10)
	LIBGCC_FLAGS := -static-libgcc
	else
	LIBGCC_FLAGS := -Wl,-rpath,\$$ORIGIN
	endif

	ifeq (${uname_P},sparc)
	$(WAZUH_LIB): $(WAZUHEXT_LIB) $(AR_PROGRAMS_DEPS)
		$(OSSEC_SHARED) $(OSSEC_CFLAGS) -mimpure-text -o $@ $(LIBGCC_FLAGS) -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
	else
	$(WAZUH_LIB): $(WAZUHEXT_LIB) $(AR_PROGRAMS_DEPS)
		$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ $(LIBGCC_FLAGS) -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
	endif
else
ifneq (,$(filter ${uname_S},AIX HP-UX))
$(WAZUH_LIB): $(WAZUHEXT_LIB) $(AR_PROGRAMS_DEPS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) $^ ${OSSEC_LIBS} -o $@ -static-libgcc
else # JNote : Linux 這邊會跑
$(WAZUH_LIB): $(WAZUHEXT_LIB) $(AR_PROGRAMS_DEPS)
	$(OSSEC_SHARED) $(OSSEC_CFLAGS) -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive ${OSSEC_LIBS}
endif
endif
endif
endif

# ************ Line:2048-2060 ************ os_auth 的功能
#### os_auth #######

os_auth_c := ${wildcard os_auth/*.c}
os_auth_o := $(os_auth_c:.c=.o)

os_auth/%.o: os_auth/%.c
	${OSSEC_CC} ${OSSEC_CFLAGS} -I./os_auth -DARGV0=\"wazuh-authd\" -c $^ -o $@

agent-auth: addagent/validate.o os_auth/main-client.o os_auth/ssl.o os_auth/check_cert.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@

wazuh-authd: addagent/validate.o os_auth/main-server.o os_auth/local-server.o os_auth/ssl.o os_auth/check_cert.o os_auth/config.o os_auth/authcom.o os_auth/auth.o os_auth/key_request.o
	${OSSEC_CCBIN} ${OSSEC_LDFLAGS} $^ ${OSSEC_LIBS} -o $@




# ************ Line:2416-2596 ************ clean
####################
#### Clean #########
####################

clean: clean-test clean-internals clean-external clean-windows clean-framework clean-config

clean-test:
	rm -Rf coverage-report/
	find . -name "*.gcno" -exec rm {} \;
	find . -name "*.gcda" -exec rm {} \;

clean-external: clean-wpython
ifneq ($(wildcard external/*/*),)
	rm -f ${cjson_o} $(EXTERNAL_JSON)libcjson.*
	-cd ${EXTERNAL_ZLIB} && ${MAKE} -f Makefile.in distclean
	-cd ${EXTERNAL_ZLIB} && ${MAKE} -f win32/Makefile.gcc clean
	rm -f ${EXTERNAL_ZLIB}/Makefile ${EXTERNAL_ZLIB}/zconf.h
	-cd ${EXTERNAL_OPENSSL} && ${MAKE} distclean
	-cd ${EXTERNAL_LIBYAML} && ${MAKE} distclean
	-cd ${EXTERNAL_CURL} && ${MAKE} distclean
	rm -f ${procps_o} $(PROCPS_LIB)
	rm -f $(sqlite_o) $(EXTERNAL_SQLITE)/libsqlite3.*
	-cd ${EXTERNAL_AUDIT} && ${MAKE} distclean
	-cd ${EXTERNAL_LIBFFI} && ${MAKE} clean
	rm -f $(msgpack_o) $(EXTERNAL_MSGPACK)libmsgpack.a
	-${MAKE} -C $(EXTERNAL_BZIP2) clean
	rm -rf $(EXTERNAL_GOOGLE_TEST)lib
	rm -rf $(EXTERNAL_GOOGLE_TEST)build
	-cd ${EXTERNAL_LIBPLIST} && ${MAKE} clean && rm -rf bin/*
	-cd ${EXTERNAL_LIBPCRE2} && ${MAKE} distclean && rm include/*
	rm -rf ${POPT_BUILD_DIR}
	rm -rf ${RPM_BUILD_DIR}

	ifneq ($(wildcard external/libdb/build_unix/*),)
		cd ${EXTERNAL_LIBDB} && ${MAKE} realclean
	endif

	ifneq ($(wildcard external/libarchive/Makefile),)
		cd ${EXTERNAL_LIBARCHIVE} && ${MAKE} clean
	endif

	ifneq ($(wildcard external/jemalloc/Makefile),)
		cd ${EXTERNAL_JEMALLOC} && ${MAKE} clean
	endif

	ifneq ($(wildcard external/pacman/lib/libalpm/*),)
		rm -f $(EXTERNAL_PACMAN)lib/libalpm/libalpm.a
		rm -f $(EXTERNAL_PACMAN)lib/libalpm/*.o
	endif
endif

clean-wpython:
ifneq ($(wildcard external/cpython/*),)
	-cd ${EXTERNAL_CPYTHON} && ${MAKE} clean && ${MAKE} distclean
endif

clean-deps:
	rm -rf $(EXTERNAL_DIR) $(EXTERNAL_CPYTHON) external/$(WPYTHON_TAR)

clean-internals: clean-unit-tests
	rm -f $(BUILD_SERVER)
	rm -f $(BUILD_AGENT)
	rm -f $(BUILD_LIBS)
	rm -f ${os_zlib_o}
	rm -f ${os_xml_o}
	rm -f ${os_regex_o}
	rm -f ${os_net_o}
	rm -f ${shared_o} shared/debug_op_proc.o shared/file_op_proc.o
	rm -f ${config_o}
	rm -f ${os_maild_o}
	rm -f ${crypto_o}
	rm -f ${os_csyslogd_o}
	rm -f ${os_dbd_o}
	rm -f ${os_agentlessd_o}
	rm -f ${os_execd_o}
	rm -f ${os_logcollector_o} ${os_logcollector_eventchannel_o}
	rm -f ${remoted_o}
	rm -f ${report_o}
	rm -f ${client_agent_o}
	rm -f ${addagent_o}
	rm -f ${active_response_o} ${active_response_programs} firewall-drop
	rm -f ${util_o} ${util_programs}
	rm -f ${rootcheck_o} rootcheck.a
	rm -f ${syscheck_o} ${syscheck_eventchannel_o}
	rm -f ${monitor_o}
	rm -f ${os_auth_o}
	rm -f ${all_analysisd_o} ${all_analysisd_libs} analysisd/compiled_rules/compiled_rules.h analysisd/logmsg.o
	rm -f ${integrator_o}
	rm -f ${wmodulesd_o} ${wmodules_o} $(wildcard wazuh_modules/agent_upgrade/agent/*.o)
	rm -f ${wdb_o}
	rm -f ${SELINUX_MODULE}
	rm -f ${SELINUX_POLICY}
	rm -f $(WAZUH_LIB)
	rm -rf $(DBSYNC)build
	rm -rf $(RSYNC)build
	rm -rf $(SHARED_UTILS_TEST)build
	rm -rf $(SYSCOLLECTOR)build
	rm -rf $(SYSINFO)build
	rm -rf libwazuhext
	rm -rf libstdc++.so.6
	rm -rf libgcc_s.so.1

clean-unit-tests:
	rm -f ${wrappers_syscheck_o}
	rm -f ${wrappers_shared_o}
	rm -f ${wrappers_common_o}
	rm -f ${wrappers_externals_o}
	rm -f ${wrappers_externals_audit_o}
	rm -f ${wrappers_externals_bzip2_o}
	rm -f ${wrappers_externals_zlib_o}
	rm -f ${wrappers_externals_cJSON_o}
	rm -f ${wrappers_externals_openssl_o}
	rm -f ${wrappers_externals_procpc_o}
	rm -f ${wrappers_externals_sqlite_o}
	rm -f ${wrappers_externals_pcre2_o}
	rm -f ${wrappers_libc_o}
	rm -f ${wrappers_linux_o}
	rm -f ${wrappers_macos_o}
	rm -f ${wrappers_macos_libc_o}
	rm -f ${wrappers_macos_posix_o}
	rm -f ${wrappers_posix_o}
	rm -f ${wrappers_wazuh_o}
	rm -f ${wrappers_wazuh_os_crypto_o}
	rm -f ${wrappers_wazuh_os_execd_o}
	rm -f ${wrappers_wazuh_os_net_o}
	rm -f ${wrappers_wazuh_os_regex_o}
	rm -f ${wrappers_wazuh_os_xml_o}
	rm -f ${wrappers_wazuh_shared_o}
	rm -f ${wrappers_wazuh_syscheckd_o}
	rm -f ${wrappers_wazuh_wazuh_db_o}
	rm -f ${wrappers_wazuh_wazuh_modules_o}
	rm -f ${wrappers_wazuh_monitord_o}
	rm -f ${wrappers_wazuh_os_auth_o}
	rm -f ${wrappers_wazuh_addagent_o}
	rm -f ${wrappers_wazuh_config_o}
	rm -f ${wrappers_windows_o}
	rm -f ${wrappers_windows_lib_o}
	rm -f ${wrappers_windows_posix_o}
	rm -f ${wrappers_client_agent_o}
	rm -f ${wrappers_wazuh_remoted_o}
	rm -f ${wrappers_wazuh_analysisd_o}
	rm -f ${wrappers_logcollector_o}
	rm -f ${wrappers_macos_o}
	rm -f ${wrappers_data_provider_o}

clean-framework:
	${MAKE} -C ../framework clean

clean-windows:
	rm -f libwazuh.a
	rm -f libwazuhshared.dll
	rm -f libwazuhext.dll
	rm -f wazuh_modules/syscollector/*.o wazuh_modules/syscollector/*.obj
	rm -f win32/LICENSE.txt
	rm -f win32/help_win.txt
	rm -f win32/internal_options.conf
	rm -f win32/default-local_internal_options.conf
	rm -f win32/default-ossec.conf
	rm -f win32/restart-ossec.cmd
	rm -f win32/route-null.cmd
	rm -f win32/route-null-2012.cmd
	rm -f win32/netsh.cmd
	rm -f win32/netsh-win-2016.cmd
	rm -f win32/default-ossec-pre6.conf
	rm -f win32/restart-wazuh.exe
	rm -f win32/route-null.exe
	rm -f win32/netsh.exe
	rm -f ${win32_o} ${win32_ui_o} win32/win_service_rk.o
	rm -f win32/icon.o win32/resource.o
	rm -f ${WINDOWS_BINS}
	rm -f win32/wazuh-agent-*.exe
	rm -f win32/libwinpthread-1.dll
	rm -f win32/VERSION
	rm -f win32/REVISION
	rm -f win32/libstdc++-6.dll
	rm -f win32/libgcc_s_dw2-1.dll
	rm -f win32/libgcc_s_sjlj-1.dll

clean-config:
	rm -f ../etc/ossec.mc
	rm -f Config.OS
