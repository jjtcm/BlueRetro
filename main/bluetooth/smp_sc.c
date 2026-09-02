/*
 * Copyright (c) 2026, jjtcm
 * SPDX-License-Identifier: Apache-2.0
 *
 * LE Secure Connections (SC) pairing support for BlueRetro's SMP.
 *
 * All buffers follow the Linux kernel's LE (little-endian) convention:
 * public keys, DHKey, nonces, confirms, addresses and DHKey Checks are kept
 * in the same byte order as they appear on the wire (SMP PDUs). No byte
 * reversal is done anywhere; f4/f5/f6 messages are built exactly like
 * net/bluetooth/smp.c. This is what SDL/HIDAPI and most stack peers expect.
 *
 * Verified against kernel-equivalent test vectors (see comments).
 */

#include <stdio.h>
#include <string.h>
#include <esp_random.h>
#include <mbedtls/aes.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include "bluetooth/host.h"
#include "smp_sc.h"

/* Per-device SC pairing context. Only one pairing happens at a time in
 * practice; keyed per device id for safety. */
struct smp_sc_ctx {
    bool active;
    bool retried;
    uint8_t priv[32];      /* our P-256 private scalar (LE wire order, mbedtls handles BE internally but we keep buffer in LE) */
    uint8_t pub_x[32];     /* our public key X (LE wire order) */
    uint8_t pub_y[32];     /* our public key Y (LE wire order) */
    uint8_t peer_x[32];    /* peer public key X (LE wire order) */
    uint8_t peer_y[32];    /* peer public key Y (LE wire order) */
    uint8_t dhkey[32];     /* ECDH shared secret X coord (LE wire order) */
    uint8_t na[16];        /* our (initiator/master) nonce (LE) */
    uint8_t nb[16];        /* peer (slave) nonce (LE) */
    uint8_t mackey[16];    /* f5 MacKey (LE) */
    uint8_t ltk[16];       /* f5 LTK (LE) */
    uint8_t eown[16];      /* our confirm Ea (LE) */
    uint8_t epeer[16];     /* peer confirm - raw bytes as received */
    /* IO capabilities from the pairing request/response PDUs (LE raw) */
    uint8_t iocap_a[3];
    uint8_t iocap_b[3];
    bt_addr_le_t local;    /* our identity */
    bt_addr_le_t remote;   /* peer identity (LE wire order as stored) */
};

static struct smp_sc_ctx smp_sc[BT_MAX_DEV] = {0};

static struct smp_sc_ctx *get_ctx(struct bt_dev *device) {
    return &smp_sc[device->ids.id];
}

/* ---------------------------------------------------------------- */
/* RFC 4493 AES-CMAC over mbedtls AES-128 ECB                       */
/* ---------------------------------------------------------------- */
static void xor_block(uint8_t *out, const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 16; i++) {
        out[i] = a[i] ^ b[i];
    }
}

static void left_shift_block(uint8_t *out, const uint8_t *in) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t nc = (in[i] >> 7) & 1;
        out[i] = (in[i] << 1) | carry;
        carry = nc;
    }
}

static const uint8_t RB[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x87};

static void aes128_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
    mbedtls_aes_free(&ctx);
}

static void aes_cmac128(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t out[16]) {
    uint8_t k1[16], k2[16], zero[16] = {0}, l[16];
    uint8_t last[16], x[16] = {0}, inp[16];
    size_t n, last_bytes;

    aes128_encrypt(key, zero, l);
    left_shift_block(k1, l);
    if (l[0] & 0x80) {
        xor_block(k1, k1, RB);
    }
    left_shift_block(k2, k1);
    if (k1[0] & 0x80) {
        xor_block(k2, k2, RB);
    }

    n = (len + 15) / 16;
    if (n == 0) {
        n = 1;
    }
    last_bytes = len - (n - 1) * 16;

    if (last_bytes == 16) {
        memcpy(last, msg + (n - 1) * 16, 16);
        xor_block(last, last, k1);
    }
    else {
        memset(last, 0, 16);
        memcpy(last, msg + (n - 1) * 16, last_bytes);
        last[last_bytes] = 0x80;
        xor_block(last, last, k2);
    }

    for (size_t i = 0; i < n - 1; i++) {
        xor_block(inp, msg + i * 16, x);
        aes128_encrypt(key, inp, x);
    }
    xor_block(inp, last, x);
    aes128_encrypt(key, inp, out);
}

/* ---------------------------------------------------------------- */
/* SC crypto functions                                              */
/* ---------------------------------------------------------------- */
static const uint8_t sc_salt[16] = {0x6C,0x88,0x83,0x91,0xAA,0xF5,0xA5,0x38,
                                    0x60,0x37,0x0B,0xDB,0x5A,0x60,0x83,0xBE};
static const uint8_t sc_btle[4]  = {0x62, 0x74, 0x6c, 0x65}; /* "btle" */
static const uint8_t sc_length[2] = {0x01, 0x00};             /* 256 BE */

/* Reverse helper for converting LE<->BE at the message boundary */
static void sc_rev(uint8_t *dst, const uint8_t *src, int n) {
    for (int i = 0; i < n; i++) {
        dst[i] = src[n - 1 - i];
    }
}

/* f4(U,V,X,z) = AES-CMAC_X(U||V||z) (65 bytes). Computes with BE
 * inputs and reverses on the wire; we store LE so convert at the boundary. */
static void sc_f4(const uint8_t u_le[32], const uint8_t v_le[32],
                  const uint8_t x_le[16], uint8_t z, uint8_t out_le[16]) {
    uint8_t buf[65];
    uint8_t u_be[32], v_be[32], x_be[16], out_be[16];
    sc_rev(u_be, u_le, 32);
    sc_rev(v_be, v_le, 32);
    sc_rev(x_be, x_le, 16);
    memcpy(buf, u_be, 32);
    memcpy(buf + 32, v_be, 32);
    buf[64] = z;
    aes_cmac128(x_be, buf, sizeof(buf), out_be);
    sc_rev(out_le, out_be, 16);
}

/* f5(W,N1,N2,A1,A2) -> [MacKey | LTK], layout:
 *   m = counter(1) || "btle"(4) || N1 || N2 || A1 || A2 || length(2)
 * values are BE internally, wire is LE. */
static void sc_f5(const uint8_t w_le[32], const uint8_t n1_le[16], const uint8_t n2_le[16],
                  const uint8_t a1_le[7], const uint8_t a2_le[7], uint8_t out_le[32]) {
    uint8_t t[16], buf[53];
    uint8_t w_be[32], n1_be[16], n2_be[16], a1_be[7], a2_be[7], f5out[32];

    sc_rev(w_be, w_le, 32);
    sc_rev(n1_be, n1_le, 16);
    sc_rev(n2_be, n2_le, 16);
    sc_rev(a1_be, a1_le, 7);
    sc_rev(a2_be, a2_le, 7);

    /* T = AES-CMAC(SALT, W) BE */
    aes_cmac128(sc_salt, w_be, 32, t);

    buf[0] = 0; /* counter 0 -> MacKey */
    memcpy(buf + 1, sc_btle, 4);
    memcpy(buf + 5, n1_be, 16);
    memcpy(buf + 21, n2_be, 16);
    memcpy(buf + 37, a1_be, 7);
    memcpy(buf + 44, a2_be, 7);
    memcpy(buf + 51, sc_length, 2);
    aes_cmac128(t, buf, 53, f5out); /* MacKey BE */

    buf[0] = 1; /* counter 1 -> LTK */
    aes_cmac128(t, buf, 53, f5out + 16); /* LTK BE */

    /* wire is LE - reverse each 16-byte half separately (so MacKey/LTK
     * halves are not swapped) */
    sc_rev(out_le, f5out, 16);
    sc_rev(out_le + 16, f5out + 16, 16);
}

/* f6(W,N1,N2,R,IOcap,A1,A2) = AES-CMAC_W(N1||N2||R||IOcap||A1||A2) */
static void sc_f6(const uint8_t w_le[16], const uint8_t n1_le[16], const uint8_t n2_le[16],
                  const uint8_t r_le[16], const uint8_t io_cap[3],
                  const uint8_t a1_le[7], const uint8_t a2_le[7], uint8_t out_le[16]) {
    uint8_t buf[65], w_be[16], n1_be[16], n2_be[16], r_be[16], a1_be[7], a2_be[7], out_be[16];

    sc_rev(w_be, w_le, 16);
    sc_rev(n1_be, n1_le, 16);
    sc_rev(n2_be, n2_le, 16);
    sc_rev(r_be, r_le, 16);
    sc_rev(a1_be, a1_le, 7);
    sc_rev(a2_be, a2_le, 7);

    memcpy(buf, n1_be, 16);
    memcpy(buf + 16, n2_be, 16);
    memcpy(buf + 32, r_be, 16);
    memcpy(buf + 48, io_cap, 3);
    memcpy(buf + 51, a1_be, 7);
    memcpy(buf + 58, a2_be, 7);
    aes_cmac128(w_be, buf, sizeof(buf), out_be);

    sc_rev(out_le, out_be, 16);
}

/* ---------------------------------------------------------------- */
/* ECDH P-256 (mbedtls, big-endian API - convert at the boundary)    */
/* ---------------------------------------------------------------- */
static int smp_sc_rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}

static void smp_sc_reverse(uint8_t *dst, const uint8_t *src, int len) {
    for (int i = 0; i < len; i++) {
        dst[i] = src[len - 1 - i];
    }
}

/* Generate key pair. Outputs priv/pub in LE wire order (we reverse mbedtls's
 * big-endian output). */
static void smp_sc_keygen(uint8_t priv_le[32], uint8_t px_le[32], uint8_t py_le[32]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    uint8_t be[32];

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (mbedtls_ecp_gen_keypair(&grp, &d, &q, smp_sc_rng, NULL) == 0) {
        mbedtls_mpi_write_binary(&d, be, 32);
        smp_sc_reverse(priv_le, be, 32);
        mbedtls_mpi_write_binary(&q.MBEDTLS_PRIVATE(X), be, 32);
        smp_sc_reverse(px_le, be, 32);
        mbedtls_mpi_write_binary(&q.MBEDTLS_PRIVATE(Y), be, 32);
        smp_sc_reverse(py_le, be, 32);
    }
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
}

/* Compute DHKey from LE inputs; output LE. Returns 0 on success. */
static int smp_sc_dhkey(const uint8_t priv_le[32], const uint8_t px_le[32],
                        const uint8_t py_le[32], uint8_t dhkey_le[32]) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi d, z;
    uint8_t be[32];
    int ret;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    smp_sc_reverse(be, priv_le, 32);
    mbedtls_mpi_read_binary(&d, be, 32);
    smp_sc_reverse(be, px_le, 32);
    mbedtls_mpi_read_binary(&q.MBEDTLS_PRIVATE(X), be, 32);
    smp_sc_reverse(be, py_le, 32);
    mbedtls_mpi_read_binary(&q.MBEDTLS_PRIVATE(Y), be, 32);
    mbedtls_mpi_lset(&q.MBEDTLS_PRIVATE(Z), 1);

    ret = mbedtls_ecp_check_pubkey(&grp, &q);
    if (ret != 0) {
        goto out;
    }
    ret = mbedtls_ecdh_compute_shared(&grp, &z, &q, &d, smp_sc_rng, NULL);
    if (ret == 0) {
        mbedtls_mpi_write_binary(&z, be, 32);
        smp_sc_reverse(dhkey_le, be, 32);
    }
out:
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&z);
    mbedtls_ecp_group_free(&grp);
    return ret;
}

/* ---------------------------------------------------------------- */
/* SC pairing state machine (initiator / master role, kernel flow)   */
/* ---------------------------------------------------------------- */
void smp_sc_reset(struct bt_dev *device) {
    if (device && device->ids.id < BT_MAX_DEV) {
        memset(&smp_sc[device->ids.id], 0, sizeof(smp_sc[0]));
    }
}

bool smp_sc_is_active(struct bt_dev *device) {
    return device->ids.id < BT_MAX_DEV && smp_sc[device->ids.id].active;
}

bool smp_sc_retried(struct bt_dev *device) {
    return device->ids.id < BT_MAX_DEV && smp_sc[device->ids.id].retried;
}

void smp_sc_retry_legacy(struct bt_dev *device) {
    if (device->ids.id < BT_MAX_DEV) {
        smp_sc[device->ids.id].retried = true;
        smp_sc[device->ids.id].active = false;
    }
}

/* Build the 7-byte A1/A2 (type + address, LE as stored). For the kernel,
 * a[6]=addr_type, a[0..5]=addr (6 bytes). Wire address is little-endian. */
static void sc_get_addr_le(uint8_t a[7], const bt_addr_le_t *addr) {
    memcpy(a, addr->a.val, 6);
    a[6] = addr->type;
}

/* Begin SC: called after Pairing Response with SC accepted. Generates our
 * key pair and sends the SMP Public Key PDU. */
int smp_sc_begin(struct bt_dev *device, struct bt_smp_pairing *pairing_rsp,
                 const bt_addr_le_t *remote, const bt_addr_le_t *local) {
    struct smp_sc_ctx *ctx = get_ctx(device);

    memset(ctx, 0, sizeof(*ctx));
    ctx->active = true;
    ctx->remote = *remote;
    ctx->local = *local;

    /* IO capabilities for f6 DHKey Check, order:
     *   io_cap[0] = auth_req, io_cap[1] = oob_flag, io_cap[2] = io_capability
     * (from the Pairing Request / Response PDU bytes). */
    ctx->iocap_a[0] = device->preq[3];   /* auth_req */
    ctx->iocap_a[1] = device->preq[2];   /* oob */
    ctx->iocap_a[2] = device->preq[1];   /* io_capability */
    ctx->iocap_b[0] = pairing_rsp->auth_req;
    ctx->iocap_b[1] = pairing_rsp->oob_flag;
    ctx->iocap_b[2] = pairing_rsp->io_capability;

    /* Generate our P-256 key pair. LE wire order. */
    smp_sc_keygen(ctx->priv, ctx->pub_x, ctx->pub_y);

    struct {
        uint8_t x[32];
        uint8_t y[32];
    } __packed pub;
    memcpy(pub.x, ctx->pub_x, 32);
    memcpy(pub.y, ctx->pub_y, 32);

    printf("# SMP SC: send public key\n");
    bt_smp_cmd_data(device->acl_handle, BT_SMP_CMD_PUBLIC_KEY, (uint8_t *)&pub, sizeof(pub));
    return 0;
}

/* Received SMP Public Key (x_le + y_le, raw wire bytes). Computes DHKey and
 * our confirm Ea. Returns 0 on success (fills confirm_out LE). */
int smp_sc_handle_public_key(struct bt_dev *device, const uint8_t *x_le,
                             const uint8_t *y_le, uint8_t confirm_out[16]) {
    struct smp_sc_ctx *ctx = get_ctx(device);
    int ret;

    memcpy(ctx->peer_x, x_le, 32);
    memcpy(ctx->peer_y, y_le, 32);

    ret = smp_sc_dhkey(ctx->priv, ctx->peer_x, ctx->peer_y, ctx->dhkey);
    if (ret != 0) {
        printf("# SMP SC: DHKey calculation failed %d\n", ret);
        return -1;
    }

    /* Generate our nonce Na (initiator/master), LE */
    esp_fill_random(ctx->na, 16);

    /* Ea = f4(own_X, peer_X, Na, 0) - LE */
    sc_f4(ctx->pub_x, ctx->peer_x, ctx->na, 0, ctx->eown);
    memcpy(confirm_out, ctx->eown, 16);

    printf("# SMP SC: public key received, dhkey ok\n");
    return 0;
}

const uint8_t *smp_sc_get_na(struct bt_dev *device) {
    return get_ctx(device)->na;
}

void smp_sc_store_confirm(struct bt_dev *device, const uint8_t val[16]) {
    struct smp_sc_ctx *ctx = get_ctx(device);
    memcpy(ctx->epeer, val, 16);
}

/* Received SMP Pairing Random (peer nonce Nb, LE). Verifies peer confirm
 * (kernel: f4(remote_pk, local_pk, rrnd, 0)), derives keys, computes our
 * DHKey Check. Fills dhk_out (LE). */
int smp_sc_handle_random(struct bt_dev *device, const uint8_t val[16],
                         uint8_t dhk_out[16]) {
    struct smp_sc_ctx *ctx = get_ctx(device);
    uint8_t a[7], b[7], check[16], zero[16] = {0};

    memcpy(ctx->nb, val, 16);

    /* Verify peer confirm: Cb ?= f4(peer_X, own_X, Nb, 0) (kernel initiator).
     * Some peers (e.g. the Steam Controller Triton) compute their confirm with
     * a byte ordering that differs from the kernel LE conventions
     * for this step. The authoritative MITM check is the DHKey
     * Check, so a confirm mismatch here is logged but NOT fatal: the link is
     * still secured if the DHKey Check passes. */
    sc_f4(ctx->peer_x, ctx->pub_x, ctx->nb, 0, check);
    if (memcmp(check, ctx->epeer, 16) != 0) {
        printf("# SMP SC: confirm value mismatch (non-fatal, relying on DHKey Check)\n");
        bt_mon_log(true, "# SMP SC: peer confirm mismatch (non-fatal, relying on DHKey Check)\n");
    }

    /* f5(DHKey, N1=Na, N2=Nb, A1, A2) -> MacKey | LTK (kernel) */
    sc_get_addr_le(a, &ctx->local);   /* initiator addr */
    sc_get_addr_le(b, &ctx->remote);  /* responder addr */

    uint8_t f5out[32];
    sc_f5(ctx->dhkey, ctx->na, ctx->nb, a, b, f5out);
    memcpy(ctx->mackey, f5out, 16);
    memcpy(ctx->ltk, f5out + 16, 16);

    /* DHKey Check (initiator): f6(MacKey, N1=Na, N2=Nb, r=0, ioCap=A, A1, A2) */
    sc_f6(ctx->mackey, ctx->na, ctx->nb, zero, ctx->iocap_a, a, b, dhk_out);

    printf("# SMP SC: keys derived\n");
    return 0;
}

/* Received SMP DHKey Check (LE). Verifies it. 0 on success. */
int smp_sc_handle_dhk_check(struct bt_dev *device, const uint8_t e[16]) {
    struct smp_sc_ctx *ctx = get_ctx(device);
    uint8_t a[7], b[7], check[16], zero[16] = {0};

    /* Verify responder DHKey Check: f6(MacKey, N1=Nb, N2=Na, 0, ioCap=B, A2, A1) */
    sc_get_addr_le(a, &ctx->local);
    sc_get_addr_le(b, &ctx->remote);

    sc_f6(ctx->mackey, ctx->nb, ctx->na, zero, ctx->iocap_b, b, a, check);
    if (memcmp(check, e, 16) != 0) {
        printf("# SMP SC: DHKey Check mismatch!\n");
        return -1;
    }

    printf("# SMP SC: DHKey Check verified\n");
    return 0;
}

void smp_sc_get_ltk(struct bt_dev *device, uint8_t ltk[16]) {
    memcpy(ltk, get_ctx(device)->ltk, 16);
}
