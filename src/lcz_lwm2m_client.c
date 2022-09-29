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
#include <lwm2m_engine.h>
#include "lcz_lwm2m_client.h"
#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
#include "attr.h"
#endif

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
struct lcz_lwm2m_client {
	struct lwm2m_ctx client;
	bool bootstrap_enabled;
	bool connection_started;
	bool connected;
};

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int lcz_lwm2m_client_init(const struct device *device);
static int device_reboot_cb(uint16_t obj_inst_id, uint8_t *args, uint16_t args_len);
static void set_connected(struct lwm2m_ctx *ctx, bool connected,
			  enum lwm2m_rd_client_event client_event);
static void rd_client_event(struct lwm2m_ctx *client, enum lwm2m_rd_client_event client_event);
static void reboot_work_cb(struct k_work *work);
static void on_lwm2m_event(struct lwm2m_ctx *client, enum lwm2m_rd_client_event client_event);
static void on_connected_event(struct lwm2m_ctx *client, bool connected,
			       enum lwm2m_rd_client_event client_event);
static int create_obj_if_needed(uint16_t obj_id, uint16_t obj_inst);
static int create_res_if_needed(uint16_t obj_id, uint16_t obj_inst, uint16_t res_id,
				uint16_t res_inst);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static struct lcz_lwm2m_client lwc[CONFIG_LCZ_LWM2M_RD_CLIENT_NUM];

static K_WORK_DELAYABLE_DEFINE(reboot_work, reboot_work_cb);

static sys_slist_t lwm2m_event_callback_list = SYS_SLIST_STATIC_INIT(&lwm2m_event_callback_list);

#if defined(CONFIG_LCZ_LWM2M_TRANSPORT_BLE_PERIPHERAL)
static lcz_lwm2m_client_data_ready_cb_t data_ready_cb = NULL;
#endif

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static struct lcz_lwm2m_client *get_lwc_from_ctx(struct lwm2m_ctx *ctx)
{
	struct lcz_lwm2m_client *lwc_inst;
	lwc_inst = CONTAINER_OF(ctx, struct lcz_lwm2m_client, client);
	return lwc_inst;
}

static int get_lwm2m_client_index_from_ctx(struct lwm2m_ctx *ctx)
{
	int i;
	for (i = 0; i < CONFIG_LCZ_LWM2M_RD_CLIENT_NUM; i++) {
		if (&lwc[i].client == ctx) {
			return i;
		}
	}
	LOG_ERR("did not find lwm2m client for lwm2m_ctx with server_inst %d", ctx->srv_obj_inst);
	return 0;
}

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

static void on_connected_event(struct lwm2m_ctx *client, bool connected,
			       enum lwm2m_rd_client_event client_event)
{
	sys_snode_t *node;
	struct lcz_lwm2m_client_event_callback_agent *agent;

	SYS_SLIST_FOR_EACH_NODE (&lwm2m_event_callback_list, node) {
		agent = CONTAINER_OF(node, struct lcz_lwm2m_client_event_callback_agent, node);
		if (agent->connected_callback != NULL) {
			agent->connected_callback(client, get_lwm2m_client_index_from_ctx(client),
						  connected, client_event);
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
	k_work_reschedule(&reboot_work, K_SECONDS(CONFIG_LCZ_LWM2M_CLIENT_REBOOT_DELAY_SECONDS));

	return 0;
}

static void set_connected(struct lwm2m_ctx *ctx, bool connected,
			  enum lwm2m_rd_client_event client_event)
{
	struct lcz_lwm2m_client *lwc_inst = get_lwc_from_ctx(ctx);
	lwc_inst->connected = connected;
	on_connected_event(ctx, lwc_inst->connected, client_event);
}

static void rd_client_event(struct lwm2m_ctx *client, enum lwm2m_rd_client_event client_event)
{
	switch (client_event) {
	case LWM2M_RD_CLIENT_EVENT_NONE:
		/* Do nothing */
		break;

	case LWM2M_RD_CLIENT_EVENT_BOOTSTRAP_REG_FAILURE:
		LOG_DBG("Bootstrap registration failure!");
		lcz_lwm2m_client_disconnect(get_lwm2m_client_index_from_ctx(client), false);
		break;

	case LWM2M_RD_CLIENT_EVENT_BOOTSTRAP_REG_COMPLETE:
		LOG_DBG("Bootstrap registration complete");
		break;

	case LWM2M_RD_CLIENT_EVENT_BOOTSTRAP_TRANSFER_COMPLETE:
		LOG_DBG("Bootstrap transfer complete");
		break;

	case LWM2M_RD_CLIENT_EVENT_REGISTRATION_FAILURE:
		LOG_DBG("Registration failure!");
		lcz_lwm2m_client_disconnect(get_lwm2m_client_index_from_ctx(client), false);
		break;

	case LWM2M_RD_CLIENT_EVENT_REGISTRATION_COMPLETE:
		LOG_DBG("Registration complete");
		set_connected(client, true, client_event);
		break;

	case LWM2M_RD_CLIENT_EVENT_REG_UPDATE_FAILURE:
		LOG_DBG("Registration update failure!");
		set_connected(client, false, client_event);
		break;

	case LWM2M_RD_CLIENT_EVENT_REG_UPDATE_COMPLETE:
		LOG_DBG("Server %d Registration update complete", client->srv_obj_inst);
		set_connected(client, true, client_event);
		break;

	case LWM2M_RD_CLIENT_EVENT_DEREGISTER_FAILURE:
		LOG_DBG("Deregister failure!");
		lcz_lwm2m_client_disconnect(get_lwm2m_client_index_from_ctx(client), false);
		break;

	case LWM2M_RD_CLIENT_EVENT_DISCONNECT:
		LOG_DBG("Disconnected");
		set_connected(client, false, client_event);
		break;

	case LWM2M_RD_CLIENT_EVENT_QUEUE_MODE_RX_OFF:
		/* Do nothing */
		break;

	case LWM2M_RD_CLIENT_EVENT_NETWORK_ERROR:
		LOG_DBG("Network Error");
		set_connected(client, false, client_event);
		break;
	}
	on_lwm2m_event(client, client_event);
}

static int create_obj_if_needed(uint16_t obj_id, uint16_t obj_inst)
{
	int ret;
	struct lwm2m_engine_obj_inst *obj;
	struct lwm2m_obj_path path = { 0 };
	char obj_path[LWM2M_MAX_PATH_STR_LEN];

	ret = 0;
	path.obj_id = obj_id;
	path.obj_inst_id = obj_inst;
	path.level = 2;

	obj = lwm2m_engine_get_obj_inst(&path);
	if (obj == NULL) {
		snprintk(obj_path, sizeof(obj_path), "%d/%d", obj_id, obj_inst);
		ret = lwm2m_engine_create_obj_inst(obj_path);
	}
	return ret;
}

static int create_res_if_needed(uint16_t obj_id, uint16_t obj_inst, uint16_t res_id,
				uint16_t res_inst)
{
	int ret;
	struct lwm2m_engine_res *res;
	struct lwm2m_obj_path path = { 0 };
	char res_path[LWM2M_MAX_PATH_STR_LEN];

	ret = 0;
	path.obj_id = obj_id;
	path.obj_inst_id = obj_inst;
	path.res_id = res_id;
	path.res_inst_id = res_inst;
	path.level = 4;

	res = lwm2m_engine_get_res(&path);
	if (res == NULL || res->res_instances->res_inst_id == 65535) {
		snprintk(res_path, sizeof(res_path), "%d/%d/%d/%d", obj_id, obj_inst, res_id,
			 res_inst);
		ret = lwm2m_engine_create_res_inst(res_path);
	}
	return ret;
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

	ret = create_obj_if_needed(LWM2M_OBJECT_SECURITY_ID, server_inst);
	if (ret < 0) {
		goto exit;
	}

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

#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	if (server_inst == LCZ_LWM2M_CLIENT_SERVER_INST_DEFAULT) {
		ret = attr_set_string(ATTR_ID_lwm2m_server_url, (char const *)server_url,
				      server_url_len);
		if (ret < 0) {
			goto exit;
		}
	}
#endif
	LOG_INF("Server URL: %s", server_url);

exit:
	return ret;
}

int lcz_lwm2m_client_set_security_mode(uint16_t server_inst, lcz_lwm2m_client_security_mode_t mode)
{
	int ret;
	char obj_path[LWM2M_MAX_PATH_STR_LEN];

	ret = create_obj_if_needed(LWM2M_OBJECT_SECURITY_ID, server_inst);
	if (ret < 0) {
		goto exit;
	}

	snprintk(obj_path, sizeof(obj_path), "0/%d/2", server_inst);
	ret = lwm2m_engine_set_u8(obj_path, mode);
	if (ret < 0) {
		goto exit;
	}
#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	if (server_inst == LCZ_LWM2M_CLIENT_SERVER_INST_DEFAULT) {
		ret = attr_set(ATTR_ID_lwm2m_security, ATTR_TYPE_U8, &mode,
			       sizeof(lcz_lwm2m_client_security_mode_t), NULL);
		if (ret < 0) {
			goto exit;
		}
	}
#endif
exit:
	return ret;
}

int lcz_lwm2m_client_set_key_or_id(uint16_t server_inst, uint8_t *value, uint16_t value_len)
{
	int ret;
	char obj_path[LWM2M_MAX_PATH_STR_LEN];

	ret = create_obj_if_needed(LWM2M_OBJECT_SECURITY_ID, server_inst);
	if (ret < 0) {
		goto exit;
	}

	snprintk(obj_path, sizeof(obj_path), "0/%d/3", server_inst);
	ret = lwm2m_engine_set_opaque(obj_path, value, value_len);
	if (ret < 0) {
		goto exit;
	}
#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	if (server_inst == LCZ_LWM2M_CLIENT_SERVER_INST_DEFAULT) {
		ret = attr_set_string(ATTR_ID_lwm2m_psk_id, (char const *)value, value_len);
		if (ret < 0) {
			goto exit;
		}
	}
#endif
exit:
	return ret;
}

int lcz_lwm2m_client_set_secret_key(uint16_t server_inst, uint8_t *value, uint16_t value_len)
{
	int ret;
	char obj_path[LWM2M_MAX_PATH_STR_LEN];

	ret = create_obj_if_needed(LWM2M_OBJECT_SECURITY_ID, server_inst);
	if (ret < 0) {
		goto exit;
	}

	snprintk(obj_path, sizeof(obj_path), "0/%d/5", server_inst);
	ret = lwm2m_engine_set_opaque(obj_path, value, value_len);
	if (ret < 0) {
		goto exit;
	}
#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	if (server_inst == LCZ_LWM2M_CLIENT_SERVER_INST_DEFAULT) {
		ret = attr_set_byte_array(ATTR_ID_lwm2m_psk, (char const *)value, value_len);
		if (ret < 0) {
			goto exit;
		}
	}
#endif
exit:
	return ret;
}

int lcz_lwm2m_client_set_bootstrap(uint16_t lwm2m_client_index, uint16_t server_inst, bool enable,
				   uint16_t short_server_id)
{
	int ret;
	char obj_path[LWM2M_MAX_PATH_STR_LEN];

	if (lwm2m_client_index == LCZ_LWM2M_CLIENT_IDX_DEFAULT) {
		lwc[lwm2m_client_index].bootstrap_enabled = enable;
	} else if (enable) {
		LOG_ERR("Cannot enable bootstrap on secondary LwM2M connection %d",
			lwm2m_client_index);
		ret = -ENOTSUP;
		goto exit;
	}

	if (enable && !IS_ENABLED(CONFIG_LCZ_LWM2M_RD_CLIENT_SUPPORT_BOOTSTRAP)) {
		LOG_ERR("Bootstrap support not enabled");
		ret = -ENOTSUP;
		goto exit;
	}

	ret = create_obj_if_needed(LWM2M_OBJECT_SECURITY_ID, server_inst);
	if (ret < 0) {
		goto exit;
	}

	snprintk(obj_path, sizeof(obj_path), "0/%d/1", server_inst);
	ret = lwm2m_engine_set_u8(obj_path, (uint8_t)enable);
	if (ret < 0) {
		goto exit;
	}

#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	if (server_inst == LCZ_LWM2M_CLIENT_SERVER_INST_DEFAULT) {
		ret = attr_set(ATTR_ID_lwm2m_bootstrap, ATTR_TYPE_BOOL, &enable, sizeof(bool),
			       NULL);
		if (ret < 0) {
			goto exit;
		}
	}
#endif

	if (enable) {
		LOG_DBG("Enabling bootstrap");
		/* Create 2nd instance of security object needed for bootstrap */
		snprintk(obj_path, sizeof(obj_path), "0/%d", server_inst + 1);
		ret = lwm2m_engine_create_obj_inst(obj_path);
		if (ret < 0) {
			goto exit;
		}
	} else {
		/* Delete second security instance because it is not needed */
		snprintk(obj_path, sizeof(obj_path), "0/%d", server_inst + 1);
		lwm2m_engine_delete_obj_inst(obj_path);

		/* Match Security object instance with a Server object instance with
		 * Short Server ID.
		 */
		snprintk(obj_path, sizeof(obj_path), "0/%d/10", server_inst);
		ret = lwm2m_engine_set_u16(obj_path, short_server_id);
		if (ret < 0) {
			goto exit;
		}

		ret = create_obj_if_needed(LWM2M_OBJECT_SERVER_ID, server_inst);
		if (ret < 0) {
			goto exit;
		}

		snprintk(obj_path, sizeof(obj_path), "1/%d/0", server_inst);
		ret = lwm2m_engine_set_u16(obj_path, short_server_id);
		if (ret < 0) {
			goto exit;
		}
#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
		if (server_inst == LCZ_LWM2M_CLIENT_SERVER_INST_DEFAULT) {
			ret = attr_set(ATTR_ID_lwm2m_short_id, ATTR_TYPE_U16, &short_server_id,
				       sizeof(uint16_t), NULL);
			if (ret < 0) {
				goto exit;
			}
		}
#endif
	}

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

int lcz_lwm2m_client_connect(int lwm2m_client_index, int init_sec_obj_inst, int init_srv_obj_inst,
			     char *endpoint_name, lcz_lwm2m_client_transport_t transport,
			     int security_tag)
{
	int ret = 0;
	uint32_t flags;
	struct lcz_lwm2m_client *lwc_inst = &lwc[lwm2m_client_index];

	if (lwm2m_client_index >= CONFIG_LCZ_LWM2M_RD_CLIENT_NUM) {
		ret = -EINVAL;
	} else {
		if (!lwc_inst->connection_started) {
			flags = lwc_inst->bootstrap_enabled ? LWM2M_RD_CLIENT_FLAG_BOOTSTRAP : 0;

			(void)memset(&lwc_inst->client, 0, sizeof(lwc_inst->client));
#if defined(CONFIG_LCZ_LWM2M_DTLS_SUPPORT)
			if (security_tag >= 0) {
				lwc_inst->client.tls_tag = security_tag;
			}
#endif

#if defined(CONFIG_LCZ_LWM2M_TRANSPORT_UDP)
			if (transport == LCZ_LWM2M_CLIENT_TRANSPORT_UDP) {
				lwc_inst->client.transport_name = "udp";
			}
#endif
#if defined(CONFIG_LCZ_LWM2M_TRANSPORT_BLE_PERIPHERAL)
			if (transport == LCZ_LWM2M_CLIENT_TRANSPORT_BLE) {
				lwc_inst->client.transport_name = "ble_peripheral";
			}
#endif
			if (lwc_inst->client.transport_name == NULL) {
				LOG_ERR("lcz_lwm2m_client_connect: invalid transport %d for config",
					transport);
			}

			lwm2m_rd_client_start(lwm2m_client_index, init_sec_obj_inst,
					      init_srv_obj_inst, &lwc_inst->client, endpoint_name,
					      flags, rd_client_event, NULL);
#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
			if (lwm2m_client_index == LCZ_LWM2M_CLIENT_SERVER_INST_DEFAULT) {
				(void)attr_set_string(ATTR_ID_lwm2m_endpoint,
						      (char const *)endpoint_name,
						      strlen(endpoint_name));
			}
#endif
			lwc_inst->connection_started = true;
		}
	}

	return ret;
}

int lcz_lwm2m_client_disconnect(int lwm2m_client_index, bool deregister)
{
	struct lcz_lwm2m_client *lwc_inst;

	if (lwm2m_client_index < CONFIG_LCZ_LWM2M_RD_CLIENT_NUM) {
		lwc_inst = &lwc[lwm2m_client_index];
		lwm2m_rd_client_stop(&lwc_inst->client, rd_client_event, deregister);

		lwc_inst->connection_started = false;

		if (!deregister) {
			set_connected(&lwc_inst->client, false, LWM2M_RD_CLIENT_EVENT_DISCONNECT);
		}
	}
	return 0;
}

bool lcz_lwm2m_client_is_connected(int lwm2m_client_index)
{
	if (lwm2m_client_index >= CONFIG_LCZ_LWM2M_RD_CLIENT_NUM) {
		return false;
	}
	return lwc[lwm2m_client_index].connected;
}

int lcz_lwm2m_client_set_device_manufacturer(char *value)
{
	int ret;

#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	ret = attr_set_string(ATTR_ID_lwm2m_mfg, (char const *)value, strlen(value));
	if (ret < 0) {
		goto exit;
	}
#endif
	ret = lwm2m_engine_set_res_data("3/0/0", value, strlen(value) + 1, LWM2M_RES_DATA_FLAG_RO);
exit:
	return ret;
}

int lcz_lwm2m_client_set_device_model_number(char *value)
{
	int ret;

#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	ret = attr_set_string(ATTR_ID_lwm2m_mn, (char const *)value, strlen(value));
	if (ret < 0) {
		goto exit;
	}
#endif
	ret = lwm2m_engine_set_res_data("3/0/1", value, strlen(value) + 1, LWM2M_RES_DATA_FLAG_RO);
exit:
	return ret;
}

int lcz_lwm2m_client_set_device_serial_number(char *value)
{
	int ret;

#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	ret = attr_set_string(ATTR_ID_lwm2m_sn, (char const *)value, strlen(value));
	if (ret < 0) {
		goto exit;
	}
#endif
	ret = lwm2m_engine_set_res_data("3/0/2", value, strlen(value) + 1, LWM2M_RES_DATA_FLAG_RO);
exit:
	return ret;
}

int lcz_lwm2m_client_set_device_firmware_version(char *value)
{
	int ret;

#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	ret = attr_set_string(ATTR_ID_lwm2m_fw_ver, (char const *)value, strlen(value));
	if (ret < 0) {
		goto exit;
	}
#endif
	ret = lwm2m_engine_set_res_data("3/0/3", value, strlen(value) + 1, LWM2M_RES_DATA_FLAG_RO);
exit:
	return ret;
}

int lcz_lwm2m_client_set_available_power_source(uint16_t res_inst,
						lcz_lwm2m_client_device_power_source_t *src)
{
	int ret;
	char obj_path[LWM2M_MAX_PATH_STR_LEN];

	ret = create_res_if_needed(LWM2M_OBJECT_DEVICE_ID, 0, 6, res_inst);
	if (ret < 0) {
		goto exit;
	}
#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	if (res_inst == 0) {
		ret = attr_set_uint32(ATTR_ID_lwm2m_pwr_src, *src);
		if (ret < 0) {
			goto exit;
		}
	}
#endif

	snprintk(obj_path, sizeof(obj_path), "3/0/6/%d", res_inst);
	ret = lwm2m_engine_set_res_data(obj_path, src, sizeof(uint8_t), LWM2M_RES_DATA_FLAG_RO);

exit:
	return ret;
}

int lcz_lwm2m_client_set_power_source_voltage(uint16_t res_inst, int32_t *millivolts)
{
	int ret;
	char obj_path[LWM2M_MAX_PATH_STR_LEN];

	ret = create_res_if_needed(LWM2M_OBJECT_DEVICE_ID, 0, 7, res_inst);
	if (ret < 0) {
		goto exit;
	}

#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	if (res_inst == 0) {
		ret = attr_set_signed32(ATTR_ID_lwm2m_pwr_src_volt, *millivolts);
		if (ret < 0) {
			goto exit;
		}
	}
#endif

	snprintk(obj_path, sizeof(obj_path), "3/0/7/%d", res_inst);
	ret = lwm2m_engine_set_res_data(obj_path, millivolts, sizeof(int32_t),
					LWM2M_RES_DATA_FLAG_RO);
exit:
	return ret;
}

int lcz_lwm2m_client_device_set_err(uint8_t err)
{
	return lwm2m_device_add_err(err);
}

int lcz_lwm2m_client_set_software_version(char *value)
{
	int ret;

#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	ret = attr_set_string(ATTR_ID_lwm2m_sw_ver, (char const *)value, strlen(value));
	if (ret < 0) {
		goto exit;
	}
#endif
	ret = lwm2m_engine_set_res_data("3/0/19", value, strlen(value) + 1, LWM2M_RES_DATA_FLAG_RO);
exit:
	return ret;
}

int lcz_lwm2m_client_set_hardware_version(char *value)
{
	int ret;

#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	ret = attr_set_string(ATTR_ID_lwm2m_hw_ver, (char const *)value, strlen(value));
	if (ret < 0) {
		goto exit;
	}
#endif
	ret = lwm2m_engine_set_res_data("3/0/18", value, strlen(value) + 1, LWM2M_RES_DATA_FLAG_RO);
exit:
	return ret;
}

int lcz_lwm2m_client_set_battery_status(lcz_lwm2m_client_device_battery_status_t *status)
{
	int ret;
#if defined(CONFIG_LCZ_LWM2M_CLIENT_ENABLE_ATTRIBUTES)
	ret = attr_set_uint32(ATTR_ID_lwm2m_batt_stat, *status);
	if (ret < 0) {
		goto exit;
	}

#endif

	ret = lwm2m_engine_set_res_data("3/0/20", status, sizeof(uint8_t), LWM2M_RES_DATA_FLAG_RO);
exit:
	return ret;
}

struct lwm2m_ctx *lcz_lwm2m_client_get_ctx(uint16_t index)
{
	if (index >= CONFIG_LCZ_LWM2M_RD_CLIENT_NUM) {
		LOG_WRN("Request for invalid LwM2M client index %d, returning first context",
			index);
		return &lwc[0].client;
	}
	return &lwc[index].client;
}

int lcz_lwm2m_client_register_get_time_callback(lwm2m_engine_get_data_cb_t cb)
{
	if (cb == NULL) {
		return -EINVAL;
	}
	return lwm2m_engine_register_read_callback("3/0/13", cb);
}

int lcz_lwm2m_client_register_factory_default_callback(lwm2m_engine_execute_cb_t cb)
{
	if (cb == NULL) {
		return -EINVAL;
	}
	return lwm2m_engine_register_exec_callback("3/0/5", cb);
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
	uint8_t *psk;
#if defined(CONFIG_LCZ_LWM2M_CLIENT_INIT_KCONFIG)
	uint8_t psk_bin[CONFIG_LCZ_LWM2M_SECURITY_KEY_SIZE];
#endif
#endif
	bool bootstrap;
	uint16_t short_server_id;
#if !defined(CONFIG_LCZ_LWM2M_CLIENT_DEVICE_NO_INIT)
	char *mfg;
	char *mn;
	char *sn;
	char *fw_ver;
	char *sw_ver;
	char *hw_ver;
	lcz_lwm2m_client_device_power_source_t *pwr_src_ptr;
	int32_t *pwr_src_v_ptr;
	lcz_lwm2m_client_device_battery_status_t *batt_stat_ptr;
#if defined(CONFIG_LCZ_LWM2M_CLIENT_DEVICE_INIT_KCONFIG)
	static lcz_lwm2m_client_device_power_source_t pwr_src;
	static int32_t pwr_src_v;
	static lcz_lwm2m_client_device_battery_status_t batt_stat;
	pwr_src_ptr = &pwr_src;
	pwr_src_v_ptr = &pwr_src_v;
	batt_stat_ptr = &batt_stat;
#else
	int val_len;
#endif
#endif

	ARG_UNUSED(device);

	lcz_lwm2m_client_register_reboot_callback(device_reboot_cb);

#if defined(CONFIG_LCZ_LWM2M_TRANSPORT_UDP)
#if defined(CONFIG_LCZ_LWM2M_CLIENT_INIT_KCONFIG)
	server_url = CONFIG_LCZ_LWM2M_SERVER_URL;
	sec_mode = (lcz_lwm2m_client_security_mode_t)CONFIG_LCZ_LWM2M_SECURITY_MODE;
	psk_id = CONFIG_LCZ_LWM2M_PSK_ID;
	ret = hex2bin(CONFIG_LCZ_LWM2M_PSK, strlen(CONFIG_LCZ_LWM2M_PSK), psk_bin, sizeof(psk_bin));
	if (ret == 0 || ret != sizeof(psk_bin)) {
		LOG_ERR("Could not convert PSK to binary");
		goto exit;
	}
	psk = psk_bin;
#else
	server_url = (char *)attr_get_quasi_static(ATTR_ID_lwm2m_server_url);
	ret = attr_get(ATTR_ID_lwm2m_security, &sec_mode, sizeof(sec_mode));
	if (ret < 0) {
		goto exit;
	}
	psk_id = (char *)attr_get_quasi_static(ATTR_ID_lwm2m_psk_id);
	psk = (uint8_t *)attr_get_quasi_static(ATTR_ID_lwm2m_psk);
#endif

	ret = lcz_lwm2m_client_set_server_url(0, server_url, strlen(server_url));
	if (ret < 0) {
		goto exit;
	}

	ret = lcz_lwm2m_client_set_security_mode(0, sec_mode);
	if (ret < 0) {
		goto exit;
	}

	if (sec_mode == LCZ_LWM2M_CLIENT_SECURITY_MODE_PSK) {
		ret = lcz_lwm2m_client_set_key_or_id(0, psk_id, strlen(psk_id));
		if (ret < 0) {
			goto exit;
		}

		ret = lcz_lwm2m_client_set_secret_key(0, psk, CONFIG_LCZ_LWM2M_SECURITY_KEY_SIZE);
		if (ret < 0) {
			goto exit;
		}
	}
#endif /* CONFIG_LCZ_LWM2M_TRANSPORT_UDP */

#if defined(CONFIG_LCZ_LWM2M_CLIENT_INIT_KCONFIG)
	bootstrap = (bool)CONFIG_LCZ_LWM2M_BOOTSTRAP_SETTING;
	short_server_id = CONFIG_LCZ_LWM2M_SHORT_SERVER_ID;
#else
	ret = attr_get(ATTR_ID_lwm2m_bootstrap, &bootstrap, sizeof(bootstrap));
	if (ret < 0) {
		goto exit;
	}
	ret = attr_get(ATTR_ID_lwm2m_short_id, &short_server_id, sizeof(short_server_id));
	if (ret < 0) {
		goto exit;
	}
#endif
	ret = lcz_lwm2m_client_set_bootstrap(LCZ_LWM2M_CLIENT_IDX_DEFAULT, 0, bootstrap,
					     short_server_id);
	if (ret < 0) {
		goto exit;
	}

#if !defined(CONFIG_LCZ_LWM2M_CLIENT_DEVICE_NO_INIT)
#if defined(CONFIG_LCZ_LWM2M_CLIENT_DEVICE_INIT_KCONFIG)
	mfg = CONFIG_LCZ_LWM2M_CLIENT_DEVICE_MFG;
	mn = CONFIG_LCZ_LWM2M_CLIENT_DEVICE_MN;
	sn = CONFIG_LCZ_LWM2M_CLIENT_DEVICE_SN;
	fw_ver = CONFIG_LCZ_LWM2M_CLIENT_DEVICE_FW_VER;
	pwr_src = (lcz_lwm2m_client_device_power_source_t)CONFIG_LCZ_LWM2M_CLIENT_DEVICE_PWR_SRC;
	pwr_src_v = CONFIG_LCZ_LWM2M_CLIENT_DEVICE_PWR_SRC_VOLT;
	sw_ver = CONFIG_LCZ_LWM2M_CLIENT_DEVICE_SW_VER;
	hw_ver = CONFIG_LCZ_LWM2M_CLIENT_DEVICE_HW_VER;
	batt_stat =
		(lcz_lwm2m_client_device_battery_status_t)CONFIG_LCZ_LWM2M_CLIENT_DEVICE_BATT_STAT;
#else
	mfg = (char *)attr_get_quasi_static(ATTR_ID_lwm2m_mfg);
	mn = (char *)attr_get_quasi_static(ATTR_ID_lwm2m_mn);
	sn = (char *)attr_get_quasi_static(ATTR_ID_lwm2m_sn);
	fw_ver = (char *)attr_get_quasi_static(ATTR_ID_lwm2m_fw_ver);
	pwr_src_ptr = attr_get_pointer(ATTR_ID_lwm2m_pwr_src, &val_len);
	if (pwr_src_ptr == NULL) {
		goto exit;
	}
	pwr_src_v_ptr = attr_get_pointer(ATTR_ID_lwm2m_pwr_src_volt, &val_len);
	if (pwr_src_v_ptr == NULL) {
		goto exit;
	}
	sw_ver = (char *)attr_get_quasi_static(ATTR_ID_lwm2m_sw_ver);
	hw_ver = (char *)attr_get_quasi_static(ATTR_ID_lwm2m_hw_ver);
	batt_stat_ptr = attr_get_pointer(ATTR_ID_lwm2m_batt_stat, &val_len);
	if (batt_stat_ptr == NULL) {
		goto exit;
	}
#endif /* CONFIG_LCZ_LWM2M_CLIENT_DEVICE_INIT_KCONFIG */
	ret = lcz_lwm2m_client_set_device_manufacturer(mfg);
	if (ret < 0) {
		goto exit;
	}
	ret = lcz_lwm2m_client_set_device_model_number(mn);
	if (ret < 0) {
		goto exit;
	}
	ret = lcz_lwm2m_client_set_device_serial_number(sn);
	if (ret < 0) {
		goto exit;
	}
	ret = lcz_lwm2m_client_set_device_firmware_version(fw_ver);
	if (ret < 0) {
		goto exit;
	}
	ret = lcz_lwm2m_client_set_available_power_source(0, pwr_src_ptr);
	if (ret < 0) {
		goto exit;
	}
	ret = lcz_lwm2m_client_set_power_source_voltage(0, pwr_src_v_ptr);
	if (ret < 0) {
		goto exit;
	}
	ret = lcz_lwm2m_client_set_software_version(sw_ver);
	if (ret < 0) {
		goto exit;
	}
	ret = lcz_lwm2m_client_set_hardware_version(hw_ver);
	if (ret < 0) {
		goto exit;
	}
	ret = lcz_lwm2m_client_set_battery_status(batt_stat_ptr);
	if (ret < 0) {
		goto exit;
	}
#endif /* !CONFIG_LCZ_LWM2M_CLIENT_DEVICE_NO_INIT */

	LOG_DBG("LwM2M client initialized");
exit:
	return ret;
}

void lcz_lwm2m_client_reboot(void)
{
	(void)device_reboot_cb(0, NULL, 0);
}

#if defined(CONFIG_LCZ_LWM2M_TRANSPORT_BLE_PERIPHERAL)
void lcz_lwm2m_client_register_data_ready_cb(lcz_lwm2m_client_data_ready_cb_t cb)
{
	data_ready_cb = cb;
}

lcz_lwm2m_client_data_ready_cb_t lcz_lwm2m_client_get_data_ready_cb(void)
{
	return data_ready_cb;
}
#endif
