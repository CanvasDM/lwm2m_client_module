/**
 * @file lcz_lwm2m_transport_ble_peripheral.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_lwm2m_ble_peripheral, CONFIG_LCZ_LWM2M_CLIENT_LOG_LEVEL);

#include <fcntl.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <init.h>
#include <sys/printk.h>
#include <posix/sys/eventfd.h>
#include <bluetooth/conn.h>
#include <bluetooth/gatt.h>
#include <bluetooth/gatt_dm.h>
#include <bluetooth/services/dfu_smp.h>
#include <bluetooth/bluetooth.h>
#include <mgmt/mgmt.h>
#include <mgmt/mcumgr/smp_bt.h>
#include <zcbor_common.h>
#include <zcbor_encode.h>
#include <zcbor_decode.h>
#include <zcbor_bulk/zcbor_bulk_priv.h>

#include <lcz_lwm2m.h>
#include "lcz_bluetooth.h"
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_PERIPHERAL)
#include "lcz_pki_auth_smp.h"
#endif
#include "lcz_lwm2m_client.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define EVENTFD_DATA_READY 1

/* How much extra time to give a tunnel beyond the registration lifetime */
#define TUNNEL_TIMEOUT_GRACE 10 /* seconds */

/* Return values from the transport recv function */
#define RECV_ERR -1
#define RECV_AGAIN 0
#define RECV_STOP 1

struct queue_entry_t {
	void *fifo_reserved;
	size_t length;
	uint8_t data[1];
};

struct smp_notification {
	struct bt_dfu_smp_header header;
	uint8_t buffer[1];
} __packed;

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int lcz_lwm2m_transport_ble_peripheral_init(const struct device *dev);

static void eventfd_close(int fd);

static int lwm2m_transport_ble_peripheral_start(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_ble_peripheral_send(struct lwm2m_ctx *client_ctx, const uint8_t *data,
					       uint32_t datalen);
static int lwm2m_transport_ble_peripheral_recv(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_ble_peripheral_close(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_ble_peripheral_is_connected(struct lwm2m_ctx *client_ctx);
static void lwm2m_transport_ble_peripheral_tx_pending(struct lwm2m_ctx *client_ctx, bool pending);
static char *lwm2m_transport_ble_peripheral_print_addr(struct lwm2m_ctx *client_ctx,
						       const struct sockaddr *addr);

static int smp_coap_open_tunnel(struct mgmt_ctxt *ctxt);
static int smp_coap_tunnel_data(struct mgmt_ctxt *ctxt);
static int smp_coap_close_tunnel(struct mgmt_ctxt *ctxt);
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_PERIPHERAL)
static int smp_coap_tunnel_enc_data(struct mgmt_ctxt *ctxt);
static int send_tunnel_enc_data(struct lwm2m_ctx *client_ctx, psa_key_id_t aead_key,
				const uint8_t *data, uint32_t datalen);
#endif
static int send_tunnel_data(struct lwm2m_ctx *client_ctx, const uint8_t *data, uint32_t datalen);

static int add_to_queue(struct k_fifo *queue, const uint8_t *data, size_t len);

static void bt_connected(struct bt_conn *conn, uint8_t conn_err);
static void bt_disconnected(struct bt_conn *conn, uint8_t reason);
static void bt_security_changed(struct bt_conn *conn, bt_security_t level,
				enum bt_security_err err);

static void tunnel_id_timeout_handler(struct k_work *work);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static const struct lwm2m_transport_procedure ble_peripheral_transport = {
	.start = lwm2m_transport_ble_peripheral_start,
	.send = lwm2m_transport_ble_peripheral_send,
	.recv = lwm2m_transport_ble_peripheral_recv,
	.close = lwm2m_transport_ble_peripheral_close,
	.is_connected = lwm2m_transport_ble_peripheral_is_connected,
	.tx_pending = lwm2m_transport_ble_peripheral_tx_pending,
	.print_addr = lwm2m_transport_ble_peripheral_print_addr,
};

static const struct mgmt_handler coap_mgmt_handlers[] = {
    [LCZ_COAP_MGMT_ID_OPEN_TUNNEL] = {
        .mh_read = NULL,
        .mh_write = smp_coap_open_tunnel,
    },
    [LCZ_COAP_MGMT_ID_TUNNEL_DATA] = {
        .mh_read = NULL,
        .mh_write = smp_coap_tunnel_data,
    },
    [LCZ_COAP_MGMT_ID_CLOSE_TUNNEL] = {
        .mh_read = NULL,
        .mh_write = smp_coap_close_tunnel,
    },
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_PERIPHERAL)
    [LCZ_COAP_MGMT_ID_TUNNEL_ENC_DATA] = {
        .mh_read = NULL,
        .mh_write = smp_coap_tunnel_enc_data,
    },
#endif
};

static struct mgmt_group coap_mgmt_group = {
	.mg_handlers = coap_mgmt_handlers,
	.mg_handlers_count = (sizeof(coap_mgmt_handlers) / sizeof(coap_mgmt_handlers[0])),
	.mg_group_id = CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP,
};

static struct bt_conn_cb conn_callbacks = {
	.connected = bt_connected,
	.disconnected = bt_disconnected,
	.security_changed = bt_security_changed,
};

/** Currently active tunnel */
static int transport_tunnel_id = 0;

/* Work to time out our tunnel ID */
static struct k_work_delayable tunnel_id_timeout_work;

/** SMP transport socket */
static int smp_socket = -1;

/* Tunnel states */
static bool server_tunnel_open = false;

/** Currently active BT connection */
static struct bt_conn *active_ble_conn = NULL;

/** Queue for storing receive messages */
static struct k_fifo rx_queue;

/** Mutex to protect access to shared data */
static struct k_mutex smp_mutex;

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
/** @brief Close an eventfd socket
 *
 * Without CONFIG_POSIX_API, there is no API to close an eventfd socket.
 * This is what close() would do if it worked.
 *
 * @param[in] fd Eventfd to close
 */
static void eventfd_close(int fd)
{
	const struct fd_op_vtable *efd_vtable;
	struct k_mutex *lock;
	void *obj;

	obj = z_get_fd_obj_and_vtable(fd, &efd_vtable, &lock);
	if (obj != NULL && lock != NULL) {
		(void)k_mutex_lock(lock, K_FOREVER);
		efd_vtable->close(obj);
		z_free_fd(fd);
		k_mutex_unlock(lock);
	}
}

static int lwm2m_transport_ble_peripheral_start(struct lwm2m_ctx *client_ctx)
{
	/* Create the eventfd file descriptor */
	smp_socket = eventfd(0, EFD_NONBLOCK);
	client_ctx->sock_fd = smp_socket;
	return 0;
}

static int lwm2m_transport_ble_peripheral_send(struct lwm2m_ctx *client_ctx, const uint8_t *data,
					       uint32_t datalen)
{
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_PERIPHERAL)
	psa_key_id_t aead_key = PSA_KEY_HANDLE_INIT;
#endif
	int err = -ENOTCONN;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&smp_mutex, K_FOREVER);

	if (server_tunnel_open && active_ble_conn) {
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_PERIPHERAL)
		if (lcz_pki_auth_smp_periph_get_keys(&aead_key, NULL, NULL) == 0) {
			/* If we can get a key, send an encrypted message */
			err = send_tunnel_enc_data(client_ctx, aead_key, data, datalen);
		} else
#endif
		{
			/* If we can't get a key, send an unencrypted message */
			err = send_tunnel_data(client_ctx, data, datalen);
		}
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&smp_mutex);

	return err;
}

static int lwm2m_transport_ble_peripheral_recv(struct lwm2m_ctx *client_ctx)
{
	struct queue_entry_t *item;
	struct sockaddr from_addr;
	eventfd_t event_val;
	int rc = -1;

	/* Create an empty address */
	memset(&from_addr, 0, sizeof(from_addr));

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&smp_mutex, K_FOREVER);

	/* Clear the event FD for now */
	(void)eventfd_read(client_ctx->sock_fd, &event_val);

	if (server_tunnel_open) {
		/* Fetch the packet from the queue */
		item = k_fifo_get(&rx_queue, K_NO_WAIT);
		if (item != NULL) {
			/* Send the received packet to the CoAP handler */
			lwm2m_coap_receive(client_ctx, item->data, item->length, &from_addr);
			k_free(item);
		}

		/* Don't allow the function to be called again by default */
		rc = RECV_STOP;

		/* If there is still data left in the queue, make the socket readable */
		if (!k_fifo_is_empty(&rx_queue)) {
			event_val = EVENTFD_DATA_READY;
			(void)eventfd_write(client_ctx->sock_fd, event_val);

			/* This function should be called again */
			rc = RECV_AGAIN;
		}
	} else {
		/* Tunnel isn't open */
		rc = RECV_ERR;
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&smp_mutex);

	/* On error, call the fault callback */
	if (rc <= RECV_ERR) {
		if (client_ctx->fault_cb != NULL) {
			client_ctx->fault_cb(client_ctx, -EIO);
		}
	}

	return rc;
}

static int lwm2m_transport_ble_peripheral_close(struct lwm2m_ctx *client_ctx)
{
	struct queue_entry_t *item;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&smp_mutex, K_FOREVER);

	/* Close the BT connection */
	if (active_ble_conn != NULL) {
		bt_conn_disconnect(active_ble_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		bt_conn_unref(active_ble_conn);
		active_ble_conn = NULL;
	}

	/* Tunnel is closed */
	server_tunnel_open = false;

	/* Close the socket */
	eventfd_close(smp_socket);
	client_ctx->sock_fd = -1;
	smp_socket = -1;

	/* Empty the receive queue */
	do {
		item = k_fifo_get(&rx_queue, K_NO_WAIT);
		if (item != NULL) {
			k_free(item);
		}
	} while (item != NULL);

	/* Release the mutex lock for our data */
	k_mutex_unlock(&smp_mutex);

	return 0;
}

static int lwm2m_transport_ble_peripheral_is_connected(struct lwm2m_ctx *client_ctx)
{
	return server_tunnel_open;
}

static void lwm2m_transport_ble_peripheral_tx_pending(struct lwm2m_ctx *client_ctx, bool pending)
{
	static bool pending_state = false;
	lcz_lwm2m_client_data_ready_cb_t cb;

	/* Update the advertising flag on change */
	if (pending != pending_state) {
		/* Save the new state */
		pending_state = pending;

		/* Call the handler to update the advertising flag */
		cb = lcz_lwm2m_client_get_data_ready_cb();
		if (cb != NULL) {
			cb(pending_state);
		}
	}
}

static char *lwm2m_transport_ble_peripheral_print_addr(struct lwm2m_ctx *client_ctx,
						       const struct sockaddr *addr)
{
	static char addr_str[BT_ADDR_LE_STR_LEN];
	const bt_addr_le_t *ble_addr;

	if (active_ble_conn != NULL) {
		ble_addr = bt_conn_get_dst(active_ble_conn);
		if (ble_addr != NULL) {
			bt_addr_le_to_str(ble_addr, addr_str, sizeof(addr_str));
			return addr_str;
		}
	}
	return "<unknown bt>";
}

/* Handler for SMP Open Tunnel message */
static int smp_coap_open_tunnel(struct mgmt_ctxt *ctxt)
{
	uint32_t tunnel_id;
	struct zcbor_string key;
	zcbor_state_t *zsd = ctxt->cnbd->zs;
	zcbor_state_t *zse = ctxt->cnbe->zs;
	eventfd_t event_val;

	/* Decode the CBOR payload */
	if (zcbor_map_start_decode(zsd) == false || zcbor_tstr_decode(zsd, &key) == false ||
	    key.len != strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID) ||
	    strncmp(key.value, LCZ_COAP_CBOR_KEY_TUNNEL_ID, strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID)) !=
		    0 ||
	    zcbor_uint32_decode(zsd, &tunnel_id) == false || zcbor_map_end_decode(zsd) == false) {
		return MGMT_ERR_EUNKNOWN;
	}

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&smp_mutex, K_FOREVER);

	if (tunnel_id == 0) {
		/* Tunnel ID of zero is an error */
		LOG_ERR("Malformed open tunnel with ID = 0");
	} else if (tunnel_id == transport_tunnel_id) {
		/* This is our active tunnel. Echo the same tunnel ID back to the client. */
	} else if (transport_tunnel_id == 0) {
		/* We don't have a tunnel yet. Use the ID provided and echo it back to the client. */
		transport_tunnel_id = tunnel_id;
	} else {
		/* This tunnel ID doesn't match what we expect */
		LOG_ERR("Received unexpected open tunnel with ID = %d", tunnel_id);

		/* Reply with tunnel ID 0 to reject the tunnel */
		tunnel_id = 0;
	}

	/* Check to see if we have a valid tunnel opening */
	if (tunnel_id != 0) {
		/* Restart the ID timeout work */
		k_work_reschedule_for_queue(
			&k_sys_work_q, &tunnel_id_timeout_work,
			K_SECONDS(CONFIG_LCZ_LWM2M_ENGINE_DEFAULT_LIFETIME + TUNNEL_TIMEOUT_GRACE));

		server_tunnel_open = true;

		/* Signal the event FD that data is ready to be read */
		event_val = EVENTFD_DATA_READY;
		(void)eventfd_write(smp_socket, event_val);
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&smp_mutex);

	/* Send the response */
	if (zcbor_tstr_put_lit(zse, LCZ_COAP_CBOR_KEY_TUNNEL_ID) &&
	    zcbor_uint32_put(zse, tunnel_id)) {
		return MGMT_ERR_EOK;
	} else {
		return MGMT_ERR_ENOMEM;
	}
}

/* Handler for SMP Tunnel Data message */
static int smp_coap_tunnel_data(struct mgmt_ctxt *ctxt)
{
	uint32_t tunnel_id = 0;
	struct zcbor_string data;
	zcbor_state_t *zsd = ctxt->cnbd->zs;
	zcbor_state_t *zse = ctxt->cnbe->zs;
	eventfd_t event_val;
	int rc = 0;
	bool ok;
	size_t decoded;

	struct zcbor_map_decode_key_val tunnel_data_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(i, zcbor_uint32_decode, &tunnel_id),
		ZCBOR_MAP_DECODE_KEY_VAL(d, zcbor_bstr_decode, &data)
	};

#if defined(CONFIG_LCZ_PKI_AUTH_SMP_PERIPHERAL)
	/* If we are authorized, we shouldn't be getting the unencrypted message */
	if (lcz_pki_auth_smp_periph_get_keys(NULL, NULL, NULL) == 0) {
		LOG_ERR("smp_coap_tunnel_data: Connection is authorized, expected encrypted tunnel data");
		rc = -EPERM;
	}
#endif

	/* Parse the input */
	if (rc == 0) {
		ok = zcbor_map_decode_bulk(zsd, tunnel_data_decode, ARRAY_SIZE(tunnel_data_decode),
					   &decoded) == 0;
		if (!ok || data.len == 0) {
			LOG_ERR("smp_coap_tunnel_data: Invalid input");
			rc = -EINVAL;
		}
	}

	/* Validate the tunnel ID */
	if (rc == 0) {
		if (tunnel_id != transport_tunnel_id) {
			/* Just ignore this message and return an "error" */
			tunnel_id = 0;
		} else if (server_tunnel_open) {
			/* Acquire a mutex lock for our data */
			k_mutex_lock(&smp_mutex, K_FOREVER);

			/* Restart the ID timeout work */
			k_work_reschedule_for_queue(
				&k_sys_work_q, &tunnel_id_timeout_work,
				K_SECONDS(CONFIG_LCZ_LWM2M_ENGINE_DEFAULT_LIFETIME +
					  TUNNEL_TIMEOUT_GRACE));

			/* Add it to our RX queue */
			if (add_to_queue(&rx_queue, data.value, data.len) == 0) {
				/* Signal the event FD that data is ready to be read */
				event_val = EVENTFD_DATA_READY;
				(void)eventfd_write(smp_socket, event_val);
			}

			/* Release the mutex lock for our data */
			k_mutex_unlock(&smp_mutex);
		}
	}

	/* Send the response */
	if (zcbor_tstr_put_lit(zse, LCZ_COAP_CBOR_KEY_TUNNEL_ID) &&
	    zcbor_uint32_put(zse, tunnel_id)) {
		return MGMT_ERR_EOK;
	} else {
		return MGMT_ERR_ENOMEM;
	}
}

/* Handler for SMP Close Tunnel message */
static int smp_coap_close_tunnel(struct mgmt_ctxt *ctxt)
{
	uint32_t tunnel_id;
	struct zcbor_string key;
	zcbor_state_t *zsd = ctxt->cnbd->zs;
	zcbor_state_t *zse = ctxt->cnbe->zs;

	if (zcbor_map_start_decode(zsd) == false || zcbor_tstr_decode(zsd, &key) == false ||
	    key.len != strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID) ||
	    strncmp(key.value, LCZ_COAP_CBOR_KEY_TUNNEL_ID, strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID)) !=
		    0 ||
	    zcbor_uint32_decode(zsd, &tunnel_id) == false || zcbor_map_end_decode(zsd) == false) {
		return MGMT_ERR_EUNKNOWN;
	}

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&smp_mutex, K_FOREVER);

	/* Tunnel is closed */
	server_tunnel_open = false;
	transport_tunnel_id = 0;
	k_work_cancel_delayable(&tunnel_id_timeout_work);

	/* Release the mutex lock for our data */
	k_mutex_unlock(&smp_mutex);

	/* Send the response */
	if (zcbor_tstr_put_lit(zse, LCZ_COAP_CBOR_KEY_TUNNEL_ID) &&
	    zcbor_uint32_put(zse, tunnel_id)) {
		return MGMT_ERR_EOK;
	} else {
		return MGMT_ERR_ENOMEM;
	}
}

#if defined(CONFIG_LCZ_PKI_AUTH_SMP_PERIPHERAL)
/* Handler for SMP Tunnel Encrypted Data message */
static int smp_coap_tunnel_enc_data(struct mgmt_ctxt *ctxt)
{
	uint32_t tunnel_id = 0;
	struct zcbor_string data;
	zcbor_state_t *zsd = ctxt->cnbd->zs;
	zcbor_state_t *zse = ctxt->cnbe->zs;
	eventfd_t event_val;
	int rc = 0;
	bool ok;
	size_t decoded;
	psa_key_id_t aead_key = PSA_KEY_HANDLE_INIT;
	size_t nonce_len;
	size_t plaintext_size;
	size_t plaintext_out;
	uint8_t *plaintext = NULL;

	struct zcbor_map_decode_key_val tunnel_data_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(i, zcbor_uint32_decode, &tunnel_id),
		ZCBOR_MAP_DECODE_KEY_VAL(d, zcbor_bstr_decode, &data)
	};

	/* If we are not authorized, we shouldn't be getting the encrypted message */
	if (lcz_pki_auth_smp_periph_get_keys(&aead_key, NULL, NULL) != 0) {
		LOG_ERR("smp_coap_tunnel_enc_data: Connection is not authorized, expected unencrypted tunnel data");
		rc = -EPERM;
	}

	/* Parse the input */
	if (rc == 0) {
		ok = zcbor_map_decode_bulk(zsd, tunnel_data_decode, ARRAY_SIZE(tunnel_data_decode),
					   &decoded) == 0;
		if (!ok || data.len == 0) {
			LOG_ERR("smp_coap_tunnel_enc_data: Invalid input");
			rc = -EINVAL;
		}
	}

	/* Validate the tunnel ID */
	if (rc == 0) {
		if (tunnel_id != transport_tunnel_id) {
			/* Just ignore this message and return an "error" */
			tunnel_id = 0;
		} else if (server_tunnel_open) {
			/* Acquire a mutex lock for our data */
			k_mutex_lock(&smp_mutex, K_FOREVER);

			/* Restart the ID timeout work */
			k_work_reschedule_for_queue(
				&k_sys_work_q, &tunnel_id_timeout_work,
				K_SECONDS(CONFIG_LCZ_LWM2M_ENGINE_DEFAULT_LIFETIME +
					  TUNNEL_TIMEOUT_GRACE));

			/* Calculate sizes */
			nonce_len = PSA_AEAD_NONCE_LENGTH(LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE,
							  LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG);
			plaintext_size =
				PSA_AEAD_DECRYPT_OUTPUT_SIZE(LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE,
							     LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG,
							     data.len - nonce_len);

			/* Allocate memory to hold the plaintext */
			plaintext = (uint8_t *)k_malloc(plaintext_size);
			if (plaintext == NULL) {
				LOG_ERR("smp_coap_tunnel_enc_data: Cannot allocate plaintext buffer");
				rc = -ENOMEM;
			}

			/* Decrypt the data */
			if (rc == 0) {
				rc = psa_aead_decrypt(aead_key, LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG,
						      data.value, nonce_len,
						      (uint8_t *)&transport_tunnel_id,
						      sizeof(transport_tunnel_id),
						      data.value + nonce_len, data.len - nonce_len,
						      plaintext, plaintext_size, &plaintext_out);
				if (rc != PSA_SUCCESS) {
					LOG_ERR("smp_coap_tunnel_enc_data: failed to decrypt: %d",
						rc);
				}
			}

			/* Add it to our RX queue */
			if (rc == 0) {
				if (add_to_queue(&rx_queue, plaintext, plaintext_out) == 0) {
					/* Signal the event FD that data is ready to be read */
					event_val = EVENTFD_DATA_READY;
					(void)eventfd_write(smp_socket, event_val);
				}
			}

			if (plaintext != NULL) {
				k_free(plaintext);
			}

			/* Release the mutex lock for our data */
			k_mutex_unlock(&smp_mutex);
		}
	}

	/* Send the response */
	if (zcbor_tstr_put_lit(zse, LCZ_COAP_CBOR_KEY_TUNNEL_ID) &&
	    zcbor_uint32_put(zse, tunnel_id)) {
		return MGMT_ERR_EOK;
	} else {
		return MGMT_ERR_ENOMEM;
	}
}
#endif

static int send_tunnel_data(struct lwm2m_ctx *client_ctx, const uint8_t *data, uint32_t datalen)
{
	zcbor_state_t zs[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];
	struct smp_notification *smp_notif = NULL;
	struct zcbor_string zstr;
	bool ok;
	int err = 0;
	size_t buffer_len;
	size_t payload_len;
	size_t total_len;
	uint16_t mtu;
	char *data_ptr;

	/* Compute the message size */
	buffer_len = sizeof(struct bt_dfu_smp_header) + LCZ_COAP_TUNNEL_CBOR_OVERHEAD + datalen;
	if (buffer_len > CONFIG_LCZ_LWM2M_TRANSPORT_BLE_MAX_PACKET) {
		LOG_ERR("send_tunnel_data: packet too large: %d", buffer_len);
		err = -EMSGSIZE;
	}

	/* Allocate memory to hold the message */
	if (err == 0) {
		smp_notif = (struct smp_notification *)k_malloc(buffer_len);
		if (smp_notif == NULL) {
			err = -ENOMEM;
		}
	}

	/* Build the CBOR message */
	if (err == 0) {
		zcbor_new_state(zs, sizeof(zs) / sizeof(zs[0]), smp_notif->buffer,
				LCZ_COAP_TUNNEL_CBOR_OVERHEAD + datalen, 1);
		ok = zcbor_map_start_encode(zs, 1);
		if (ok) {
			zstr.len = strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID);
			zstr.value = LCZ_COAP_CBOR_KEY_TUNNEL_ID;
			ok = zcbor_tstr_encode(zs, &zstr);
		}
		if (ok) {
			ok = zcbor_uint32_encode(zs, &transport_tunnel_id);
		}
		if (ok) {
			zstr.len = strlen(LCZ_COAP_CBOR_KEY_DATA);
			zstr.value = LCZ_COAP_CBOR_KEY_DATA;
			ok = zcbor_tstr_encode(zs, &zstr);
		}
		if (ok) {
			zstr.len = datalen;
			zstr.value = data;
			ok = zcbor_bstr_encode(zs, &zstr);
		}
		if (ok) {
			ok = zcbor_map_end_encode(zs, 1);
		}
		if (!ok) {
			/* Most likely failed because message doesn't fit into buffer */
			LOG_ERR("send_tunnel_data: Failed to encode message of %d bytes", datalen);
			err = -EMSGSIZE;
		}
	}

	/* Send the message */
	if (err == 0) {
		payload_len = (size_t)(zs[0].payload - smp_notif->buffer);
		total_len = sizeof(smp_notif->header) + payload_len;
		smp_notif->header.op = LCZ_COAP_MGMT_OP_NOTIFY;
		smp_notif->header.flags = 0;
		smp_notif->header.len_h8 = (uint8_t)((payload_len >> 8) & 0xFF);
		smp_notif->header.len_l8 = (uint8_t)((payload_len >> 0) & 0xFF);
		smp_notif->header.group_h8 = (CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 8) & 0xFF;
		smp_notif->header.group_l8 = (CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 0) & 0xFF;
		smp_notif->header.seq = 0;
		smp_notif->header.id = LCZ_COAP_MGMT_ID_TUNNEL_DATA;

		/* Send chunks of the message to fit into the MTU */
		data_ptr = (char *)smp_notif;
		mtu = bt_gatt_get_mtu(active_ble_conn);
		while (total_len > 0) {
			size_t this_len = total_len;
			if (this_len > BT_MAX_PAYLOAD(mtu)) {
				this_len = BT_MAX_PAYLOAD(mtu);
			}
			err = smp_bt_notify(active_ble_conn, data_ptr, this_len);
			if (err < 0) {
				LOG_ERR("send_tunnel_data: notify failed: %d", err);
				break;
			}
			total_len -= this_len;
			data_ptr += this_len;
		}
	}

	/* Free memory that we allocated */
	if (smp_notif != NULL) {
		k_free(smp_notif);
	}

	return err;
}

#if defined(CONFIG_LCZ_PKI_AUTH_SMP_PERIPHERAL)
static int send_tunnel_enc_data(struct lwm2m_ctx *client_ctx, psa_key_id_t aead_key,
				const uint8_t *data, uint32_t datalen)
{
	zcbor_state_t zs[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];
	struct smp_notification *smp_notif = NULL;
	struct zcbor_string zstr;
	bool ok;
	int err = 0;
	size_t buffer_len;
	size_t payload_len;
	size_t total_len;
	uint16_t mtu;
	char *data_ptr;
	size_t nonce_len;
	size_t ciphertext_size;
	size_t ciphertext_out_size;
	uint8_t *ciphertext = NULL;

	/* Compute the ciphertext size */
	nonce_len = PSA_AEAD_NONCE_LENGTH(LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE,
					  LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG);
	ciphertext_size =
		nonce_len + PSA_AEAD_ENCRYPT_OUTPUT_SIZE(LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE,
							 LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG,
							 datalen);

	/* Compute the message size */
	buffer_len =
		sizeof(struct bt_dfu_smp_header) + LCZ_COAP_TUNNEL_CBOR_OVERHEAD + ciphertext_size;
	if (buffer_len > CONFIG_LCZ_LWM2M_TRANSPORT_BLE_MAX_PACKET) {
		LOG_ERR("send_tunnel_enc_data: packet too large: %d", buffer_len);
		err = -EMSGSIZE;
	}

	/* Allocate memory for the ciphertext */
	if (err == 0) {
		ciphertext = (uint8_t *)k_malloc(ciphertext_size);
		if (ciphertext == NULL) {
			LOG_ERR("send_tunnel_enc_data: Failed to allocate ciphertext buffer of %d bytes",
				ciphertext_size);
			err = -ENOMEM;
		}
	}

	/* Allocate memory to hold the message */
	if (err == 0) {
		smp_notif = (struct smp_notification *)k_malloc(buffer_len);
		if (smp_notif == NULL) {
			LOG_ERR("send_tunnel_enc_data: Failed to allocate message buffer of %d bytes",
				buffer_len);
			err = -ENOMEM;
		}
	}

	/* Generate the nonce */
	if (err == 0) {
		err = psa_generate_random(ciphertext, nonce_len);
		if (err != PSA_SUCCESS) {
			LOG_ERR("send_tunnel_enc_data: generate random nonce failed: %d", err);
		}
	}

	/* Encrypt the data */
	if (err == 0) {
		err = psa_aead_encrypt(aead_key, LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG, ciphertext,
				       nonce_len, (uint8_t *)&transport_tunnel_id,
				       sizeof(transport_tunnel_id), data, datalen,
				       ciphertext + nonce_len, ciphertext_size - nonce_len,
				       &ciphertext_out_size);
		if (err != PSA_SUCCESS) {
			LOG_ERR("send_tunnel_enc_data: failed to encrypt: %d", err);
		}
	}

	/* Build the CBOR message */
	if (err == 0) {
		zcbor_new_state(zs, sizeof(zs) / sizeof(zs[0]), smp_notif->buffer,
				LCZ_COAP_TUNNEL_CBOR_OVERHEAD + ciphertext_size, 1);
		ok = zcbor_map_start_encode(zs, 1);
		if (ok) {
			zstr.len = strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID);
			zstr.value = LCZ_COAP_CBOR_KEY_TUNNEL_ID;
			ok = zcbor_tstr_encode(zs, &zstr);
		}
		if (ok) {
			ok = zcbor_uint32_encode(zs, &transport_tunnel_id);
		}
		if (ok) {
			zstr.len = strlen(LCZ_COAP_CBOR_KEY_DATA);
			zstr.value = LCZ_COAP_CBOR_KEY_DATA;
			ok = zcbor_tstr_encode(zs, &zstr);
		}
		if (ok) {
			zstr.len = ciphertext_size;
			zstr.value = ciphertext;
			ok = zcbor_bstr_encode(zs, &zstr);
		}
		if (ok) {
			ok = zcbor_map_end_encode(zs, 1);
		}
		if (!ok) {
			/* Most likely failed because message doesn't fit into buffer */
			LOG_ERR("send_tunnel_enc_data: Failed to encode message of %d bytes",
				ciphertext_out_size);
			err = -EMSGSIZE;
		}
	}

	/* Send the message */
	if (err == 0) {
		payload_len = (size_t)(zs[0].payload - smp_notif->buffer);
		total_len = sizeof(smp_notif->header) + payload_len;
		smp_notif->header.op = LCZ_COAP_MGMT_OP_NOTIFY;
		smp_notif->header.flags = 0;
		smp_notif->header.len_h8 = (uint8_t)((payload_len >> 8) & 0xFF);
		smp_notif->header.len_l8 = (uint8_t)((payload_len >> 0) & 0xFF);
		smp_notif->header.group_h8 = (CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 8) & 0xFF;
		smp_notif->header.group_l8 = (CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 0) & 0xFF;
		smp_notif->header.seq = 0;
		smp_notif->header.id = LCZ_COAP_MGMT_ID_TUNNEL_ENC_DATA;

		/* Send chunks of the message to fit into the MTU */
		data_ptr = (char *)smp_notif;
		mtu = bt_gatt_get_mtu(active_ble_conn);
		while (total_len > 0) {
			size_t this_len = total_len;
			if (this_len > BT_MAX_PAYLOAD(mtu)) {
				this_len = BT_MAX_PAYLOAD(mtu);
			}
			err = smp_bt_notify(active_ble_conn, data_ptr, this_len);
			if (err < 0) {
				LOG_ERR("send_tunnel_enc_data: notify failed: %d", err);
				break;
			}
			total_len -= this_len;
			data_ptr += this_len;
		}
	}

	/* Free memory that we allocated */
	if (ciphertext != NULL) {
		k_free(ciphertext);
	}
	if (smp_notif != NULL) {
		k_free(smp_notif);
	}

	return err;
}
#endif

static int add_to_queue(struct k_fifo *queue, const uint8_t *data, size_t len)
{
	struct queue_entry_t *item = NULL;
	int rc = -EINVAL;

	if (data != NULL && len > 0) {
		item = k_malloc(sizeof(struct queue_entry_t) - 1 + len);
		if (item == NULL) {
			rc = -ENOMEM;
		} else {
			item->length = len;
			memcpy(item->data, data, len);
			k_fifo_put(queue, item);
			rc = 0;
		}
	}

	return rc;
}

static void bt_connected(struct bt_conn *conn, uint8_t conn_err)
{
	/* Acquire a mutex lock for our data */
	k_mutex_lock(&smp_mutex, K_FOREVER);

	if (active_ble_conn == NULL) {
		active_ble_conn = conn;
		bt_conn_ref(conn);
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&smp_mutex);
}

static void bt_disconnected(struct bt_conn *conn, uint8_t reason)
{
	/* Acquire a mutex lock for our data */
	k_mutex_lock(&smp_mutex, K_FOREVER);

	if (active_ble_conn == conn) {
		bt_conn_unref(conn);
		active_ble_conn = NULL;

		/* The tunnel is closed if the active connection drops */
		server_tunnel_open = false;
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&smp_mutex);
}

static void bt_security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	if (err != BT_SECURITY_ERR_SUCCESS) {
		LOG_ERR("bt_security_changed: fail with level %d err %d", level, err);

		/* Try unpairing this device if this happens */
		(void)bt_unpair(BT_ID_DEFAULT, bt_conn_get_dst(conn));
	}
}

static void tunnel_id_timeout_handler(struct k_work *work)
{
	/* Clear the tunnel ID if it hasn't been used in a while */
	transport_tunnel_id = 0;
}

SYS_INIT(lcz_lwm2m_transport_ble_peripheral_init, APPLICATION,
	 CONFIG_LCZ_LWM2M_CLIENT_INIT_PRIORITY);
/**************************************************************************************************/
/* SYS INIT                                                                                       */
/**************************************************************************************************/
static int lcz_lwm2m_transport_ble_peripheral_init(const struct device *dev)
{
	/* Initialize the mutex */
	k_mutex_init(&smp_mutex);

	/* Initialize our receive queue */
	k_fifo_init(&rx_queue);

	/* Initialize the delayed work */
	k_work_init_delayable(&tunnel_id_timeout_work, tunnel_id_timeout_handler);

	/* Register for BT callbacks */
	bt_conn_cb_register(&conn_callbacks);

	/* Make sure that our group is registered with the SMP server */
	mgmt_register_group(&coap_mgmt_group);

	return lwm2m_transport_register(
		"ble_peripheral", (struct lwm2m_transport_procedure *)&ble_peripheral_transport);
}
