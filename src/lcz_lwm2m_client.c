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
#include <sys/reboot.h>
#include <sys/util.h>
#include "lcz_lwm2m_client.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int lcz_lwm2m_client_init(const struct device *device);
static int device_reboot_cb(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len);
static void set_connected(bool connected, enum lwm2m_rd_client_event client_event);
static void rd_client_event(struct lwm2m_ctx *client, enum lwm2m_rd_client_event client_event);
static void reboot_work_cb(struct k_work *work);
static void on_lwm2m_event(struct lwm2m_ctx *client, enum lwm2m_rd_client_event client_event);
static void on_connected_event(bool connected, enum lwm2m_rd_client_event client_event);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static struct {
	struct lwm2m_ctx client;
	bool bootstrap_enabled;
	bool connection_started;
	bool connected;
} lwc;

static K_WORK_DELAYABLE_DEFINE(reboot_work, reboot_work_cb);

static sys_slist_t lwm2m_event_callback_list = SYS_SLIST_STATIC_INIT(&lwm2m_event_callback_list);

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static void on_lwm2m_event(struct lwm2m_ctx *client, enum lwm2m_rd_client_event client_event)
{
	sys_snode_t *node;
	struct lcz_lwm2m_client_event_callback_agent *agent;

	SYS_SLIST_FOR_EACH_NODE (&lwm2m_event_callback_list, node) {
		agent = CONTAINER_OF(node, struct lcz_lwm2m_client_event_callback_agent, node);
		if (agent->event_callback != NULL) {
			agent->event_callback(client, client_event);
		}
	}
}

static void on_connected_event(bool connected, enum lwm2m_rd_client_event client_event)
{
	sys_snode_t *node;
	struct lcz_lwm2m_client_event_callback_agent *agent;

	SYS_SLIST_FOR_EACH_NODE(&lwm2m_event_callback_list, node) {
		agent = CONTAINER_OF(node, struct lcz_lwm2m_client_event_callback_agent, node);
		if (agent->connected_callback != NULL) {
			agent->connected_callback(connected, client_event);
		}
	}
}

static void reboot_work_cb(struct k_work *work)
{
	ARG_UNUSED(work);
	sys_reboot(SYS_REBOOT_COLD);
}

static int device_reboot_cb(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len)
{
	ARG_UNUSED(obj_inst_id);
	ARG_UNUSED(args);
	ARG_UNUSED(args_len);

	LOG_WRN("Rebooting in %d seconds", CONFIG_LCZ_LWM2M_CLIENT_REBOOT_DELAY_SECONDS);
	lcz_lwm2m_client_disconnect(lwc.connected);
	k_work_reschedule(&reboot_work, K_SECONDS(CONFIG_LCZ_LWM2M_CLIENT_REBOOT_DELAY_SECONDS));

	return 0;
}

static void set_connected(bool connected, enum lwm2m_rd_client_event client_event)
{
	lwc.connected = connected;
	on_connected_event(lwc.connected, client_event);
}

static void rd_client_event(struct lwm2m_ctx *client, enum lwm2m_rd_client_event client_event)
{
	switch (client_event) {
	case LWM2M_RD_CLIENT_EVENT_NONE:
		/* do nothing */
		break;

	case LWM2M_RD_CLIENT_EVENT_BOOTSTRAP_REG_FAILURE:
		LOG_DBG("Bootstrap registration failure!");
		lcz_lwm2m_client_disconnect(false);
		break;

	case LWM2M_RD_CLIENT_EVENT_BOOTSTRAP_REG_COMPLETE:
		LOG_DBG("Bootstrap registration complete");
		break;

	case LWM2M_RD_CLIENT_EVENT_BOOTSTRAP_TRANSFER_COMPLETE:
		LOG_DBG("Bootstrap transfer complete");
		break;

	case LWM2M_RD_CLIENT_EVENT_REGISTRATION_FAILURE:
		LOG_DBG("Registration failure!");
		lcz_lwm2m_client_disconnect(false);
		break;

	case LWM2M_RD_CLIENT_EVENT_REGISTRATION_COMPLETE:
		LOG_DBG("Registration complete");
		set_connected(true, client_event);
		break;

	case LWM2M_RD_CLIENT_EVENT_REG_UPDATE_FAILURE:
		LOG_DBG("Registration update failure!");
		set_connected(false, client_event);
		break;

	case LWM2M_RD_CLIENT_EVENT_REG_UPDATE_COMPLETE:
		LOG_DBG("Registration update complete");
		break;

	case LWM2M_RD_CLIENT_EVENT_DEREGISTER_FAILURE:
		LOG_DBG("Deregister failure!");
		lcz_lwm2m_client_disconnect(false);
		break;

	case LWM2M_RD_CLIENT_EVENT_DISCONNECT:
		LOG_DBG("Disconnected");
		set_connected(false, client_event);
		break;

	case LWM2M_RD_CLIENT_EVENT_QUEUE_MODE_RX_OFF:
		/* do nothing */
		break;

	case LWM2M_RD_CLIENT_EVENT_NETWORK_ERROR:
		LOG_DBG("Network Error");
		set_connected(false, client_event);
		break;
	}
	on_lwm2m_event(client, client_event);
}

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

	server_url_len = snprintk(server_url, server_url_len, "%s", url);
	if (server_url_len < length) {
		LOG_ERR("Server URL truncated [%s]", server_url);
		ret = -EINVAL;
		goto exit;
	}
	LOG_INF("Server URL: %s", log_strdup(server_url));

exit:
	return ret;
}

int lcz_lwm2m_client_set_security_mode(uint16_t server_inst, lcz_lwm2m_client_security_mode_t mode)
{
	char obj_path[LWM2M_MAX_PATH_STR_LEN];

	snprintk(obj_path, sizeof(obj_path), "0/%d/2", server_inst);
	return lwm2m_engine_set_u8(obj_path, mode);
}

int lcz_lwm2m_client_set_key_or_id(uint16_t server_inst, uint8_t *value, uint16_t value_len)
{
	char obj_path[LWM2M_MAX_PATH_STR_LEN];

	snprintk(obj_path, sizeof(obj_path), "0/%d/3", server_inst);
	return lwm2m_engine_set_opaque(obj_path, value, value_len);
}

int lcz_lwm2m_client_set_secret_key(uint16_t server_inst, uint8_t *value, uint16_t value_len)
{
	char obj_path[LWM2M_MAX_PATH_STR_LEN];

	snprintk(obj_path, sizeof(obj_path), "0/%d/5", server_inst);
	return lwm2m_engine_set_opaque(obj_path, value, value_len);
}

int lcz_lwm2m_client_set_bootstrap(uint16_t server_inst, bool enable, uint16_t short_server_id)
{
	int ret;
	char obj_path[LWM2M_MAX_PATH_STR_LEN];

	if (enable) {
		/* Mark 1st instance of security object as a bootstrap server */
		snprintk(obj_path, sizeof(obj_path), "0/%d/1", server_inst);
		ret = lwm2m_engine_set_u8(obj_path, 1);
		if (ret < 0) {
			goto exit;
		}

		/* Create 2nd instance of security object needed for bootstrap */
		snprintk(obj_path, sizeof(obj_path), "0/%d", server_inst + 1);
		ret = lwm2m_engine_create_obj_inst(obj_path);
		if (ret < 0) {
			goto exit;
		}
	} else {
		/* indicate non-bootstrap server */
		snprintk(obj_path, sizeof(obj_path), "0/%d/1", server_inst);
		ret = lwm2m_engine_set_u8(obj_path, 0);
		if (ret < 0) {
			goto exit;
		}

		/* delete second security instance because it is not needed */
		snprintk(obj_path, sizeof(obj_path), "0/%d", server_inst + 1);
		lwm2m_engine_create_obj_inst(obj_path);

		/* Match Security object instance with a Server object instance with
		 * Short Server ID.
		 */
		snprintk(obj_path, sizeof(obj_path), "0/%d/10", server_inst);
		ret = lwm2m_engine_set_u16(obj_path, short_server_id);
		if (ret < 0) {
			goto exit;
		}
		snprintk(obj_path, sizeof(obj_path), "1/%d/0", server_inst);
		ret = lwm2m_engine_set_u16(obj_path, short_server_id);
		if (ret < 0) {
			goto exit;
		}
	}
	lwc.bootstrap_enabled = enable;
exit:
	return ret;
}

int lcz_lwm2m_client_register_reboot_callback(lwm2m_engine_execute_cb_t cb)
{
	int ret;
	if (cb == NULL) {
		ret = -EINVAL;
		goto exit;
	}

	ret = lwm2m_engine_register_exec_callback("3/0/4", cb);

exit:
	return ret;
}

int lcz_lwm2m_client_register_event_callback(struct lcz_lwm2m_client_event_callback_agent *agent)
{
	sys_slist_append(&lwm2m_event_callback_list, &agent->node);
	return 0;
}

int lcz_lwm2m_client_unregister_event_callback(struct lcz_lwm2m_client_event_callback_agent *agent)
{
	(void)sys_slist_find_and_remove(&lwm2m_event_callback_list, &agent->node);
	return 0;
}

int lcz_lwm2m_client_connect(char *endpoint_name, lcz_lwm2m_client_transport_t transport)
{
	uint32_t flags;

	if (!lwc.connection_started) {
		flags = lwc.bootstrap_enabled ? LWM2M_RD_CLIENT_FLAG_BOOTSTRAP : 0;

		(void)memset(&lwc.client, 0, sizeof(lwc.client));
#if defined(CONFIG_LCZ_LWM2M_CLIENT_TLS_TAG)
		lwc.client.tls_tag = CONFIG_LCZ_LWM2M_CLIENT_TLS_TAG;
#endif

		if (transport == LCZ_LWM2M_CLIENT_TRANSPORT_UDP) {
			lwc.client.transport_name = "udp";
		} else {
			lwc.client.transport_name = "ble";
		}

		lwm2m_rd_client_start(&lwc.client, endpoint_name, flags, rd_client_event, NULL);
		lwc.connection_started = true;
	}

	return 0;
}

int lcz_lwm2m_client_disconnect(bool deregister)
{
	lwm2m_rd_client_stop(&lwc.client, rd_client_event, deregister);
	lwc.connection_started = false;
	if (!deregister) {
		set_connected(false, LWM2M_RD_CLIENT_EVENT_DISCONNECT);
	}
	return 0;
}

bool lcz_lwm2m_client_is_connected(void)
{
	return lwc.connected;
}

SYS_INIT(lcz_lwm2m_client_init, APPLICATION, CONFIG_LCZ_LWM2M_CLIENT_INIT_PRIORITY);
/**************************************************************************************************/
/* SYS INIT                                                                                       */
/**************************************************************************************************/
static int lcz_lwm2m_client_init(const struct device *device)
{
	int ret;
#if defined(CONFIG_LCZ_LWM2M_TRANSPORT_UDP)
	char *server_url;
	lcz_lwm2m_client_security_mode_t sec_mode;
	char *psk_id;
	char *psk;
	uint8_t psk_bin[CONFIG_LCZ_LWM2M_SECURITY_KEY_SIZE];
	bool bootstrap;
	uint16_t short_server_id;
#endif

	ARG_UNUSED(device);

	lcz_lwm2m_client_register_reboot_callback(device_reboot_cb);

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

#if defined(CONFIG_LCZ_LWM2M_SECURITY_MODE)
	sec_mode = (lcz_lwm2m_client_security_mode_t)CONFIG_LCZ_LWM2M_SECURITY_MODE;
#else
	/* this is a placeholder for a future runtime setting */
	sec_mode = LCZ_LWM2M_CLIENT_SECURITY_MODE_NO_SEC;
#endif
	ret = lcz_lwm2m_client_set_security_mode(0, sec_mode);
	if (ret < 0) {
		goto exit;
	}

	if (sec_mode == LCZ_LWM2M_CLIENT_SECURITY_MODE_PSK) {
#if defined(CONFIG_LCZ_LWM2M_PSK_ID)
		psk_id = CONFIG_LCZ_LWM2M_PSK_ID;
#else
		/* this is a placeholder for a future runtime setting */
		psk_id = "psk_id";
#endif
		ret = lcz_lwm2m_client_set_key_or_id(0, psk_id, strlen(psk_id));
		if (ret < 0) {
			goto exit;
		}

#if defined(CONFIG_LCZ_LWM2M_PSK)
		psk = CONFIG_LCZ_LWM2M_PSK;
#else
		/* this is a placeholder for a future runtime setting */
		psk = "000102030405060708090a0b0c0d0e0f";
#endif
		ret = hex2bin((const char *)psk, strlen(psk), psk_bin, sizeof(psk_bin));
		if (ret == 0 || ret != sizeof(psk_bin)) {
			LOG_ERR("Could not convert PSK to binary");
			goto exit;
		}
		ret = lcz_lwm2m_client_set_secret_key(0, psk_bin, sizeof(psk_bin));
		if (ret < 0) {
			goto exit;
		}
	}
#endif /* CONFIG_LCZ_LWM2M_TRANSPORT_UDP */

#if defined(CONFIG_LCZ_LWM2M_BOOTSTRAP)
	bootstrap = (bool)CONFIG_LCZ_LWM2M_BOOTSTRAP_SETTING;
	short_server_id = CONFIG_LCZ_LWM2M_SHORT_SERVER_ID;
#else
	/* this is a placeholder for a future runtime setting */
	bootstrap = false;
	short_server_id = 1;
#endif
	ret = lcz_lwm2m_client_set_bootstrap(0, bootstrap, short_server_id);
	if (ret < 0) {
		goto exit;
	}

	LOG_DBG("LwM2M client initialized");
exit:
	return ret;
}
