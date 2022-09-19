/**
 * @file lcz_lwm2m_client_shell.c
 *
 * Copyright (c) 2022 Laird Connectivity LLC
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(lwm2m_shell, CONFIG_LCZ_LWM2M_CLIENT_LOG_LEVEL);

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <stdlib.h>
#include <shell/shell.h>
#include "lcz_lwm2m_client.h"

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static int shell_lwm2m_err_cmd(const struct shell *shell, size_t argc, char **argv)
{
	return lcz_lwm2m_client_device_set_err((uint8_t)strtol(argv[1], NULL, 10));
}

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
SHELL_STATIC_SUBCMD_SET_CREATE(lwm2m_cmds,
			       SHELL_CMD_ARG(err, NULL, "Set LwM2M error code (3/0/11/x)",
					     shell_lwm2m_err_cmd, 2, 0),
			       SHELL_SUBCMD_SET_END /* Array terminated. */
);

SHELL_CMD_REGISTER(lwm2m, &lwm2m_cmds, "LwM2M commands", NULL);
