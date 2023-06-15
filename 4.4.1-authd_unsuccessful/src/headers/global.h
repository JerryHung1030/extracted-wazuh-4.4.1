/*
 * 以下是擷取自data_provider/include/sysinfo.h
 * wm_control.c會用到
 */
#ifndef _SYS_INFO_H
#define _SYS_INFO_H

// Define EXPORTED for any platform
#include "../shared_modules/common/commonDefs.h"
#ifdef WAZUH_UNIT_TESTING
#define EXPORTED
#else
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif
#endif


#include "../external/cJSON/cJSON.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef int(*sysinfo_networks_func)(cJSON** jsresult);
typedef int(*sysinfo_os_func)(cJSON** jsresult);
typedef int(*sysinfo_processes_func)(cJSON** jsresult);
typedef void(*sysinfo_free_result_func)(cJSON** jsresult);

#ifdef __cplusplus
}
#endif

#endif //_SYS_INFO_H
