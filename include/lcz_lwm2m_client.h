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
#include <zephyr.h>
#include <zephyr/types.h>
#include <stddef.h>

#include "lcz_lwm2m.h"

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

typedef void (*lcz_lwm2m_client_connected_cb_t)(bool connected,
						enum lwm2m_rd_client_event client_event);

struct lcz_lwm2m_client_event_callback_agent {
	sys_snode_t node;
	lwm2m_ctx_event_cb_t event_callback;
	lcz_lwm2m_client_connected_cb_t connected_callback;
};

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
 * @param server_inst instance for object 0
 * @param enable enable or disable using bootstrap
 * @param short_server_id This identifier uniquely identifies each LwM2M Server configured for
 * the LwM2M Client. This Resource MUST be set when the Bootstrap-Server Resource has a value of
 * 'false'. The values 0 and 65535 values MUST NOT be used for identifying the LwM2M Server.
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_set_bootstrap(uint16_t server_inst, bool enable, uint16_t short_server_id);

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
 * @brief Start the LwM2M client connection
 *
 * @param endpoint_name Name of the endpoint
 * @param transport Transport type
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_connect(char *endpoint_name, lcz_lwm2m_client_transport_t transport);

/**
 * @brief Disconnect the LwM2M client
 *
 * @param deregister true to trigger a deregister false to force close the connection
 * @return int 0 on success, < 0 on error
 */
int lcz_lwm2m_client_disconnect(bool deregister);

/**
 * @brief Check if the LwM2M client is connected.
 *
 * @return true LwM2M clients is connected
 * @return false LwM2M clients is NOT connected
 */
bool lcz_lwm2m_client_is_connected(void);

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_LWM2M_CLIENT_H__ */
