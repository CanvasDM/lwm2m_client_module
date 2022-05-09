/**
 * @file lcz_lwm2m_client.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_lwm2m_client, CONFIG_LCZ_LWM2M_CLIENT_LOG_LEVEL);

#include <zephyr.h>
#include <init.h>
#include "lcz_lwm2m.h"
#include "lcz_lwm2m_client.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int lcz_lwm2m_client_init(const struct device *device);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
int lcz_lwm2m_client_set_server_url(uint16_t server_inst, char *url, uint8_t length)
{
	int ret;
	char obj_path[LWM2M_MAX_PATH_STR_LEN];
	char *server_url;
	uint16_t server_url_len;
	uint8_t server_url_flags;

	snprintk(obj_path, sizeof(obj_path), "0/%d/0", server_inst);
	ret = lwm2m_engine_get_res_data(obj_path, (void **)&server_url, &server_url_len,
					&server_url_flags);
	if (ret < 0) {
		goto exit;
	}

	if (length > server_url_len) {
		ret = -EINVAL;
		LOG_ERR("URL len [%d] is longer than [%d]", length, server_url_len);
		goto exit;
	}

	server_url_len = snprintk(server_url, server_url_len, "coap%s//%s",
				  IS_ENABLED(CONFIG_LWM2M_DTLS_SUPPORT) ? "s:" : ":", url);
	if (server_url_len < length) {
		LOG_ERR("Server URL truncated [%s]", server_url);
		ret = -EINVAL;
		goto exit;
	}
	LOG_INF("Server URL: %s", log_strdup(server_url));

exit:
	return ret;
}

SYS_INIT(lcz_lwm2m_client_init, APPLICATION, CONFIG_LCZ_LWM2M_CLIENT_INIT_PRIORITY);
/**************************************************************************************************/
/* SYS INIT                                                                                       */
/**************************************************************************************************/
static int lcz_lwm2m_client_init(const struct device *device)
{
	int ret;
	char *server_url;

	ARG_UNUSED(device);

#if defined(CONFIG_LCZ_LWM2M_TRANSPORT_UDP)
#if defined(CONFIG_LCZ_LWM2M_SERVER_URL)
	server_url = CONFIG_LCZ_LWM2M_SERVER_URL;
#else
	/* this is a placeholder for a future runtime setting */
	server_url = "my.lwm2m.com:5843";
#endif
	ret = lcz_lwm2m_client_set_server_url(0, server_url, strlen(server_url));
	if (ret < 0) {
		goto exit;
	}
#endif /* CONFIG_LCZ_LWM2M_TRANSPORT_UDP */

	LOG_DBG("lwm2m client initialized");
exit:
	return ret;
}
