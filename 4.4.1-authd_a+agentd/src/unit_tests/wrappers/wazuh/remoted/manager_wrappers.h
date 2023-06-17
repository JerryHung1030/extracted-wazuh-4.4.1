/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * Feb 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef REM_MANAGER_WRAPPERS_H
#define REM_MANAGER_WRAPPERS_H

#include <cJSON.h>

cJSON *__wrap_assign_group_to_agent(const char *agent_id, const char *md5);

#endif /* REM_MANAGER_WRAPPERS_H */
