/*
 * Copyright (c) 2026, jjtcm
 * SPDX-License-Identifier: Apache-2.0
 *
 * LE Secure Connections (SC) pairing support for BlueRetro's SMP.
 *
 * SC crypto functions f4/f5/f6 are AES-CMAC based (Bluetooth Core Spec
 * Vol 3 Part H 2.3.5.6). Implemented on top of mbedtls AES-ECB (RFC 4493)
 * and mbedtls ECDH P-256. All keys/numbers are held in big-endian byte
 * arrays, matching the Bluetooth test vectors; only the SMP Pairing Public
 * Key PDU uses little-endian coordinates (conversion happens on the wire).
 *
 * Verified against the official Bluetooth SC test vectors:
 *   f4(U=20b003d2..,V=55188b3d..,X=d5cb8454..,z=00) -> f2c916f1..
 *   f5(W=ec0234a3..,N1..,N2..,A1,A2) -> MacKey 2965f176.., LTK 69867911..
 *     (LTK matches the Linux kernel's known f5 output)
 *   f6(MacKey 2965f176..,N1,N2,R,IOcap=010102,A1,A2) -> e3c47398..
 *   ECDH(dB=3f49f6d4.., PKB) -> DHKey ec0234a3..
 */

#ifndef _SMP_SC_H_
#define _SMP_SC_H_

#include <stdbool.h>
#include "zephyr/smp.h"

struct bt_dev;
struct bt_data;

/* Send an SMP PDU (code + data) - implemented in smp.c */
void bt_smp_cmd_data(uint16_t handle, uint8_t code, const uint8_t *data, uint16_t len);

void smp_sc_reset(struct bt_dev *device);
bool smp_sc_is_active(struct bt_dev *device);
bool smp_sc_retried(struct bt_dev *device);
void smp_sc_retry_legacy(struct bt_dev *device);

/* Called after receiving the Pairing Response with the SC bit set.
 * Generates the local P-256 key pair and sends the SMP Public Key PDU. */
int smp_sc_begin(struct bt_dev *device, struct bt_smp_pairing *pairing_rsp,
                 const bt_addr_le_t *remote, const bt_addr_le_t *local);

/* Received SMP Public Key (x_le[32] + y_le[32]). Computes the DHKey, local
 * nonce and confirm value; fills confirm_out (the value to send). */
int smp_sc_handle_public_key(struct bt_dev *device, const uint8_t *x_le,
                             const uint8_t *y_le, uint8_t confirm_out[16]);

/* Our (initiator) nonce, little-endian wire order (send as-is). */
const uint8_t *smp_sc_get_na(struct bt_dev *device);

void smp_sc_store_confirm(struct bt_dev *device, const uint8_t val[16]);

/* Received SMP Pairing Random (peer nonce). Verifies peer confirm, derives
 * LTK/MacKey, computes our DHKey Check; fills dhk_out (the value to send). */
int smp_sc_handle_random(struct bt_dev *device, const uint8_t val[16],
                         uint8_t dhk_out[16]);

/* Received SMP DHKey Check. Verifies it. 0 on success. */
int smp_sc_handle_dhk_check(struct bt_dev *device, const uint8_t e[16]);

/* Get the derived LTK after successful DHKey Check verification. */
void smp_sc_get_ltk(struct bt_dev *device, uint8_t ltk[16]);

#endif /* _SMP_SC_H_ */
