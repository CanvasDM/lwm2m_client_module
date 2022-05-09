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
#include <zephyr/types.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
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

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_LWM2M_CLIENT_H__ */
