#
# Copyright (c) 2022 Laird Connectivity LLC
#
# SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
#
if(CONFIG_LCZ_LWM2M_CLIENT)

zephyr_include_directories(include)

zephyr_sources(src/lcz_lwm2m_client.c)
zephyr_sources_ifdef(CONFIG_LCZ_LWM2M_TRANSPORT_BLE_PERIPHERAL
    src/lcz_lwm2m_transport_ble_peripheral.c)

endif()
