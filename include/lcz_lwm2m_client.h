/**
 * @file lcz_lwm2m_client.h
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#ifndef __LCZ_LWM2M_CLIENT_H__
#define __LCZ_LWM2M_CLIENT_H__

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <stddef.h>
#include <zephyr/zephyr.h>
#include <zephyr/types.h>
#include <zephyr/net/lwm2m.h>

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************************/
/* Global Constants, Macros and Type Definitions                                                  */
/**************************************************************************************************/
typedef enum lcz_lwm2m_client_security_mode {
	LCZ_LWM2M_CLIENT_SECURITY_MODE_PSK = 0,
	LCZ_LWM2M_CLIENT_SECURITY_MODE_RPK,
	LCZ_LWM2M_CLIENT_SECURITY_MODE_CERT,
	LCZ_LWM2M_CLIENT_SECURITY_MODE_NO_SEC,
	LCZ_LWM2M_CLIENT_SECURITY_MODE_CERT_EST,
} lcz_lwm2m_client_security_mode_t;

typedef enum lcz_lwm2m_client_transport {
	LCZ_LWM2M_CLIENT_TRANSPORT_UDP = 0,
	LCZ_LWM2M_CLIENT_TRANSPORT_BLE,
} lcz_lwm2m_client_transport_t;

typedef enum lcz_lwm2m_client_device_power_source {
	LCZ_LWM2M_CLIENT_DEV_PWR_SRC_DC = 0,
	LCZ_LWM2M_CLIENT_DEV_PWR_SRC_INT_BATT,
	LCZ_LWM2M_CLIENT_DEV_PWR_SRC_EXT_BATT,
	LCZ_LWM2M_CLIENT_DEV_PWR_SRC_FUEL_CELL,
	LCZ_LWM2M_CLIENT_DEV_PWR_SRC_POE,
	LCZ_LWM2M_CLIENT_DEV_PWR_SRC_USB,
	LCZ_LWM2M_CLIENT_DEV_PWR_SRC_AC,
	LCZ_LWM2M_CLIENT_DEV_PWR_SRC_SOLAR,
} lcz_lwm2m_client_device_power_source_t;

typedef enum lcz_lwm2m_client_device_battery_status {
	LCZ_LWM2M_CLIENT_DEV_BATT_STAT_NORMAL = 0,
	LCZ_LWM2M_CLIENT_DEV_BATT_STAT_CHARGING,
	LCZ_LWM2M_CLIENT_DEV_BATT_STAT_CHARGE_COMPLETE,
	LCZ_LWM2M_CLIENT_DEV_BATT_STAT_DAMAGED,
	LCZ_LWM2M_CLIENT_DEV_BATT_STAT_LOW,
	LCZ_LWM2M_CLIENT_DEV_BATT_STAT_NOT_INSTALLED,
	LCZ_LWM2M_CLIENT_DEV_BATT_STAT_UNKNOWN,
} lcz_lwm2m_client_device_battery_status_t;

typedef void (*lcz_lwm2m_client_connected_cb_t)(struct lwm2m_ctx *client, int lwm2m_client_index,
						bool connected,
						enum lwm2m_rd_client_event client_event);

struct lcz_lwm2m_client_event_callback_agent {
	sys_snode_t node;
	lwm2m_ctx_event_cb_t event_callback;
	lcz_lwm2m_client_connected_cb_t connected_callback;
};

/*
 * The lwm2m_client supports multiple instances, referenced by a client index. The
 * "default index" is the only index allowed to use LwM2M bootstrapping.
 */
#define LCZ_LWM2M_CLIENT_IDX_DEFAULT 0
/* The default client index will use this default server instance for object 0 */
#define LCZ_LWM2M_CLIENT_SERVER_INST_DEFAULT 0

/* Defines for SMP over BLE tunnel for CoAP/LwM2M */
#define LCZ_COAP_MGMT_OP_NOTIFY 4
#define LCZ_COAP_MGMT_ID_OPEN_TUNNEL 1
#define LCZ_COAP_MGMT_ID_TUNNEL_DATA 2
#define LCZ_COAP_MGMT_ID_CLOSE_TUNNEL 3
#define LCZ_COAP_MGMT_ID_TUNNEL_ENC_DATA 4
#define LCZ_COAP_CBOR_KEY_TUNNEL_ID "i"
#define LCZ_COAP_CBOR_KEY_DATA "d"

#define LCZ_COAP_TUNNEL_CBOR_OVERHEAD 16

#if defined(CONFIG_LCZ_LWM2M_TRANSPORT_BLE_PERIPHERAL)
typedef void (*lcz_lwm2m_client_data_ready_cb_t)(bool data_ready);
#endif

/**************************************************************************************************/
/* Global Function Prototypes                                                                     */
/**************************************************************************************************/
/**
 * @brief Set the server URL
 *
 * @param server_inst instance of the LwM2M server object
 * @param url URL string
 * @param length length of the URL string
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_server_url(uint16_t server_inst, char *url, uint8_t length);

/**
 * @brief Set the security mode for the client
 *
 * @param server_inst instance for object 0
 * @param mode security mode
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_security_mode(uint16_t server_inst, lcz_lwm2m_client_security_mode_t mode);

/**
 * @brief Set the the PSK ID or public key value
 *
 * @param server_inst instance for object 0
 * @param value key or ID value
 * @param value_len length of the key or ID
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_key_or_id(uint16_t server_inst, uint8_t *value, uint16_t value_len);

/**
 * @brief Set private key or PSK
 *
 * @param server_inst instance for object 0
 * @param value key value
 * @param value_len length of key
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_secret_key(uint16_t server_inst, uint8_t *value, uint16_t value_len);

/**
 * @brief Enable or disable bootstrap
 *
 * The lwm2m_client supports multiple instances, referenced by a client index. The
 * "default index" is the only index allowed to use LwM2M bootstrapping. Attempting to
 * enable bootstrap on other client indexes will result in an error.
 *
 * @param lwm2m client index to set bootstrap settings for
 * @param server_inst instance for object 0
 * @param enable enable or disable using bootstrap
 * @param short_server_id This identifier uniquely identifies each LwM2M Server configured for
 * the LwM2M Client. This Resource MUST be set when the Bootstrap-Server Resource has a value of
 * 'false'. The values 0 and 65535 values MUST NOT be used for identifying the LwM2M Server.
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_bootstrap(uint16_t lwm2m_client_index, uint16_t server_inst, bool enable,
				   uint16_t short_server_id);

/**
 * @brief Register a callback that will be invoked when the reboot command is executed.
 *
 * @param cb reboot callback
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_register_reboot_callback(lwm2m_engine_execute_cb_t cb);

/**
 * @brief Register a callback that will be invoked for important LwM2M events.
 *
 * @param agent Callback agent
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_register_event_callback(struct lcz_lwm2m_client_event_callback_agent *agent);

/**
 * @brief Unregister a callback that will be invoked for important LwM2M events.
 *
 * @param agent Callback agent
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_unregister_event_callback(struct lcz_lwm2m_client_event_callback_agent *agent);

/**
 * @brief Register a callback that will be invoked when resource /3/0/13 is read
 *
 * @param cb callback function
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_register_get_time_callback(lwm2m_engine_get_data_cb_t cb);

/**
 * @brief Register a callback that will be invoked before resource /3/0/13 is written.
 * This allows a user to set the data pointer to be used for the resource.
 *
 * @param cb callback function
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_register_pre_write_set_time_callback(lwm2m_engine_get_data_cb_t cb);

/**
 * @brief Register a callback that will be invoked after resource /3/0/13 is written
 *
 * @param cb callback function
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_register_post_write_set_time_callback(lwm2m_engine_set_data_cb_t cb);

/**
 * @brief Register a callback that will be invoked when resource /3/0/5 is executed
 *
 * @param cb callback function
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_register_factory_default_callback(lwm2m_engine_execute_cb_t cb);

/**
 * @brief Start the LwM2M client connection
 *
 * @param lwm2m_client_index index of the client
 * @param init_sec_obj_inst security object instance associated with the client
 * @param init_srv_obj_inst server object instance associated with the client
 * @param endpoint_name Name of the endpoint
 * @param transport Transport type
 * @param security_tag TLS security tag
 * @param load_credentials certificate loading function to support certificate security
 * This function can also be set to NULL to use PSK security instead.
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_connect(int lwm2m_client_index, int init_sec_obj_inst, int init_srv_obj_inst,
			     char *endpoint_name, lcz_lwm2m_client_transport_t transport,
			     int security_tag, load_credentials_cb_t load_credentials);

/**
 * @brief Disconnect the LwM2M client
 *
 * @param deregister true to trigger a deregister false to force close the connection
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_disconnect(int lwm2m_client_index, bool deregister);

/**
 * @brief Check if the LwM2M client is connected.
 *
 * @return true LwM2M clients is connected
 * @return false LwM2M clients is NOT connected
 */
bool lcz_lwm2m_client_is_connected(int lwm2m_client_index);

/**
 * @brief Set manufacturer
 *
 * @param value string value
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_device_manufacturer(char *value);

/**
 * @brief Set model number
 *
 * @param value string value
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_device_model_number(char *value);

/**
 * @brief Set serial number
 *
 * @param value string value
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_device_serial_number(char *value);

/**
 * @brief Set firmware version
 *
 * @param value string value
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_device_firmware_version(char *value);

/**
 * @brief Set power source of device
 *
 * @param res_inst resource instance
 * @param src power source type
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_available_power_source(uint16_t res_inst,
						lcz_lwm2m_client_device_power_source_t *src);

/**
 * @brief Source power source voltage
 *
 * @param res_inst resource instance
 * @param millivolts voltage in millivolts (mV)
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_power_source_voltage(uint16_t res_inst, int32_t *millivolts);

/**
 * @brief Set software version
 *
 * @param value string value
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_software_version(char *value);

/**
 * @brief Set hardware version
 *
 * @param value string value
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_hardware_version(char *value);

/**
 * @brief Set battery status
 *
 * @param status battery status
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_battery_status(lcz_lwm2m_client_device_battery_status_t *status);

/**
 * @brief Close all open LwM2M connections and reboot the device
 */
void lcz_lwm2m_client_reboot(void);

/**
 * @brief Set device error code (3/0/11/x)
 *
 * @param err error state (see include/zephyr/net/lwm2m.h for err defines)
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_device_set_err(uint8_t err);

#if defined(CONFIG_LCZ_LWM2M_TRANSPORT_BLE_PERIPHERAL)
/**
 * @brief Register a handler for advertising flag state changes
 *
 * The LwM2M client, when using the BLE transport, needs to signal the availability of LwM2M
 * data to be sent to the gateway. This is typically done through a flag in the BLE
 * advertisement. Rather than attempt to control the advertisement data from inside
 * of the LwM2M client, an application-specific handler must be provided.
 *
 * The registered handler will be called whenever the state of "Has LwM2M data to send"
 * changes. The handler is called from the context of the LwM2M thread.
 *
 * The LwM2M client only supports registration of a single handler. If the registered
 * handler needs to be removed, this function can be called and passed a NULL pointer
 * for the handler function.
 *
 * @param[in] handler Function pointer to handler for advertising flag state changes
 * or NULL to remove the previous handler
 */
void lcz_lwm2m_client_register_data_ready_cb(lcz_lwm2m_client_data_ready_cb_t cb);

/**
 * @brief Get the current handler for advertising flag state changes
 *
 * This function returns the pointer to the handler function registered by
 * lcz_lwm2m_client_register_data_ready_cb().
 *
 * @return Pointer to the handler function for advertising flag state changes
 * or NULL if no handler is registered.
 */
lcz_lwm2m_client_data_ready_cb_t lcz_lwm2m_client_get_data_ready_cb(void);
#endif /* CONFIG_LCZ_LWM2M_TRANSPORT_BLE_PERIPHERAL */

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_LWM2M_CLIENT_H__ */
