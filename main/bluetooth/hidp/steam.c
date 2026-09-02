/*
 * Copyright (c) 2026, jjtcm
 * SPDX-License-Identifier: Apache-2.0
 *
 * Steam Controller 2026 (Triton) over Bluetooth LE.
 *
 * Triton does NOT use HOGP the way Xbox/DualSense do. SDL/Android talk to
 * Valve's proprietary GATT service (same UUID base as the classic Steam
 * Controller). It exposes an input notification characteristic with report
 * IDs 0x45/0x47 and a rumble output characteristic (report 0x80, suffix
 * 0xB5). Rumble needs a ~40 ms resend while active (hardware safety
 * timeout ~50 ms). No lizard-off write is needed for Triton - SDL's Android
 * BLE backend skips it.
 *
 * Protocol reference: SDL HIDDeviceBLESteamController + SDL_hidapi_steam_triton,
 * Pairing: hold RB + B + Steam on the controller.
 */

#include <stdio.h>
#include <string.h>
#include <esp_timer.h>
#include "bluetooth/host.h"
#include "bluetooth/hci.h"
#include "bluetooth/att.h"
#include "bluetooth/att_cfg.h"
#include "bluetooth/mon.h"
#include "zephyr/att.h"
#include "zephyr/gatt.h"
#include "zephyr/uuid.h"
#include "tools/util.h"
#include "steam.h"

#define STEAM_RUMBLE_RESEND_MS 40
#define STEAM_RUMBLE_REARM_MS 400

enum {
    STEAM_STATE_FIND_SVC = 0,
    STEAM_STATE_FIND_CHARS,
    STEAM_STATE_FIND_CCC,
    STEAM_STATE_EN_CCC,
    STEAM_STATE_DONE,
};

struct steam_dev {
    esp_timer_handle_t timer_hdl;
    uint16_t service_start;
    uint16_t service_end;
    uint16_t input_value_handle;
    uint16_t input_ccc_handle;
    uint16_t report_value_handle;
    uint16_t rumble_value_handle;
    uint8_t report_id;
    /* Rumble state (resend every ~40 ms while active) */
    uint32_t rumble_ms_left;
    uint8_t rumble_weak;
    uint8_t rumble_strong;
    bool rumble_pending;
    bool ready;
};

static struct steam_dev steam_dev[BT_MAX_DEV] = {0};

static struct steam_dev *get_ins(struct bt_dev *device) {
    return &steam_dev[device->ids.id];
}

/* Valve service/characteristic family match on over-the-air (LSB first) UUID */
static bool steam_uuid_is_valve_family(const uint8_t u[16]) {
    static const uint8_t tail[12] = {0xF3, 0xE5, 0x31, 0x71, 0x56, 0x38,
                                     0x02, 0xB4, 0x13, 0x43, 0x35, 0x17};
    return u[13] == 0x6C && u[14] == 0x0F && u[15] == 0x10 && memcmp(u, tail, 12) == 0;
}

static void steam_send_rumble(struct bt_dev *device, uint8_t weak, uint8_t strong) {
    struct steam_dev *ins = get_ins(device);
    uint16_t handle = ins->rumble_value_handle ?
        ins->rumble_value_handle : ins->report_value_handle;
    if (!handle) {
        return;
    }
    /* SDL Android BLE backend (HIDDeviceBLESteamController.writeReport):
     * the Triton output report characteristic (suffix 0xB5 for report 0x80)
     * receives the MsgHapticRumble payload with the report_id (byte 0) and
     * the trailing right.gain byte stripped:
     *   [0]   type = 0
     *   [1:2] intensity (u16 LE) = 0
     *   [3:4] left.speed (u16 LE) = strong * 257
     *   [5]   left.gain (i8) = 0
     *   [6:7] right.speed (u16 LE) = weak * 257
     * = 8 bytes. */
    uint8_t payload[8] = {0};
    payload[0] = 0; /* type */
    payload[1] = 0; /* intensity lo */
    payload[2] = 0; /* intensity hi */
    uint16_t left = (uint16_t)strong * 257u;
    payload[3] = (uint8_t)(left & 0xff);
    payload[4] = (uint8_t)(left >> 8);
    payload[5] = 0; /* left.gain */
    uint16_t right = (uint16_t)weak * 257u;
    payload[6] = (uint8_t)(right & 0xff);
    payload[7] = (uint8_t)(right >> 8);

    /* Use write-with-response like the working SDL
     * implementations. Some Valve characteristics reject
     * write-without-response, so a WRITE_REQ is required. */
    bt_att_cmd_write_req(device->acl_handle, handle, payload, sizeof(payload));
}

static void steam_timer_cb(void *arg) {
    uint32_t dev_id = (uint32_t)(uintptr_t)arg;
    struct bt_dev *device = NULL;
    struct steam_dev *ins = &steam_dev[dev_id];

    bt_host_get_dev_from_id(dev_id, &device);
    if (device == NULL) {
        return;
    }

    /* Device disconnected or slot reused: stop ticking until a new Steam
     * connection restarts the timer. NOTE: Staleness is signalled by
     * BT_DEV_DEVICE_FOUND / ids.type, which bt_host_reset_dev() clears. */
    if (!atomic_test_bit(&device->flags, BT_DEV_DEVICE_FOUND)
        || device->ids.type != BT_STEAM) {
        if (ins->timer_hdl) {
            esp_timer_stop(ins->timer_hdl);
            esp_timer_delete(ins->timer_hdl);
            ins->timer_hdl = NULL;
        }
        return;
    }

    if (!ins->ready || !ins->input_value_handle) {
        return;
    }

    /* Rumble resend while active */
    if (ins->rumble_ms_left) {
        if (ins->rumble_ms_left > STEAM_RUMBLE_RESEND_MS) {
            ins->rumble_ms_left -= STEAM_RUMBLE_RESEND_MS;
        }
        else {
            ins->rumble_ms_left = 0;
        }
        steam_send_rumble(device, ins->rumble_weak, ins->rumble_strong);
    }
}

static void steam_timer_start(struct bt_dev *device) {
    struct steam_dev *ins = get_ins(device);

    if (ins->timer_hdl) {
        esp_timer_stop(ins->timer_hdl);
        esp_timer_delete(ins->timer_hdl);
        ins->timer_hdl = NULL;
    }

    const esp_timer_create_args_t timer_args = {
        .callback = &steam_timer_cb,
        .arg = (void *)(uintptr_t)device->ids.id,
        .name = "steam_timer"
    };
    if (esp_timer_create(&timer_args, &ins->timer_hdl) == ESP_OK) {
        esp_timer_start_periodic(ins->timer_hdl, STEAM_RUMBLE_RESEND_MS * 1000);
    }
    else {
        printf("# Steam Triton: timer create FAILED\n");
    }
}

static void steam_on_ready(struct bt_dev *device) {
    struct steam_dev *ins = get_ins(device);

    ins->ready = true;
    printf("# Steam Triton: CONNECTED (input report 0x%02X)\n", ins->report_id);
    bt_mon_log(true, "# Steam Triton: CONNECTED (input report 0x%02X)\n", ins->report_id);

    /* Request ~7.5-11 ms connection interval like SDL */
    struct hci_cp_le_conn_update le_conn_update = {
        .conn_interval_min = 6,
        .conn_interval_max = 9,
        .conn_latency = 0,
        .supervision_timeout = 600,
        .min_ce_len = 0,
        .max_ce_len = 0,
    };
    le_conn_update.handle = device->acl_handle;
    bt_hci_le_conn_update(&le_conn_update);

    steam_timer_start(device);

    atomic_set_bit(&device->flags, BT_DEV_HID_INIT_DONE);
    device->hid_state = STEAM_STATE_DONE;
}

static void steam_find_svc_rsp(struct bt_dev *device, uint32_t att_len,
        uint8_t *data, uint32_t data_len) {
    struct steam_dev *ins = get_ins(device);
    struct bt_att_group_data *elem = NULL;
    struct bt_att_group_data *last = NULL;
    uint32_t elem_cnt;

    if (data) {
        elem_cnt = (att_len - 2) / data_len;
        if (elem_cnt == 0) {
            goto svc_done;
        }
        elem = (struct bt_att_group_data *)data;

        for (uint32_t i = 0; i < elem_cnt; i++) {
            /* 128-bit service UUIDs have 20 bytes entries */
            if (data_len == 20 && steam_uuid_is_valve_family(elem[i].value)
                && elem[i].value[12] == STEAM_SVC_SUFFIX) {
                ins->service_start = elem[i].start_handle;
                ins->service_end = elem[i].end_handle;
            }
        }

        last = (struct bt_att_group_data *)((uint8_t *)data + data_len * (elem_cnt - 1));
        /* Once the Valve service is found we don't need to walk the remaining groups */
        if (ins->service_start == 0 && last->end_handle < 0xFFFF) {
            bt_att_cmd_read_group_req_uuid16(device->acl_handle,
                last->end_handle + 1, BT_UUID_GATT_PRIMARY);
            return;
        }
    }

svc_done:
    if (ins->service_start == 0) {
        printf("# Steam Triton: Valve service not found, disconnecting\n");
        bt_mon_log(true, "# Steam Triton: Valve service not found, disconnecting\n");
        bt_hci_disconnect(device);
        return;
    }

    printf("# Steam Triton: Valve service handles %#x..%#x\n",
        ins->service_start, ins->service_end);
    bt_mon_log(true, "# Steam Triton: Valve service handles %#x..%#x\n",
        ins->service_start, ins->service_end);

    device->hid_state = STEAM_STATE_FIND_CHARS;
    bt_att_cmd_find_info_req(device->acl_handle, ins->service_start, ins->service_end);
}

static void steam_find_chars_rsp(struct bt_dev *device, uint32_t att_len,
        uint8_t *info, uint32_t format) {
    struct steam_dev *ins = get_ins(device);
    struct bt_att_info_16 *info16 = NULL;
    struct bt_att_info_128 *info128 = NULL;
    uint32_t elem_cnt;
    uint16_t last_handle = 0;

    if (info) {
        if (format == BT_ATT_INFO_16) {
            info16 = (struct bt_att_info_16 *)info;
            elem_cnt = (att_len - 2) / sizeof(*info16);
            if (elem_cnt == 0) {
                goto chars_done;
            }
            last_handle = info16[elem_cnt - 1].handle;
        }
        else {
            info128 = (struct bt_att_info_128 *)info;
            elem_cnt = (att_len - 2) / sizeof(*info128);
            if (elem_cnt == 0) {
                goto chars_done;
            }
            last_handle = info128[elem_cnt - 1].handle;
        }

        for (uint32_t i = 0; i < elem_cnt; i++) {
            uint16_t handle;
            const uint8_t *uuid128;
            if (format == BT_ATT_INFO_16) {
                handle = info16[i].handle;
                uuid128 = NULL;
            }
            else {
                handle = info128[i].handle;
                uuid128 = info128[i].uuid;
            }

            if (uuid128 && steam_uuid_is_valve_family(uuid128)) {
                uint8_t suffix = uuid128[12];
                if (suffix == STEAM_CHR_INPUT_STATE) {
                    /* Prefer 0x47 if already seen; otherwise take 0x45 */
                    if (ins->report_id != STEAM_TRITON_REPORT_STATE_TS) {
                        ins->input_value_handle = handle;
                        ins->report_id = STEAM_TRITON_REPORT_STATE_BLE;
                    }
                }
                else if (suffix == STEAM_CHR_INPUT_STATE_TS) {
                    ins->input_value_handle = handle;
                    ins->report_id = STEAM_TRITON_REPORT_STATE_TS;
                }
                else if (suffix == STEAM_CHR_REPORT) {
                    ins->report_value_handle = handle;
                }
                else if (suffix == STEAM_CHR_RUMBLE) {
                    ins->rumble_value_handle = handle;
                }
            }
            else if (uuid128 && (*(uint16_t *)&uuid128[12] == 0x2902)) {
                /* CCC descriptor encoded in a 128-bit format response */
                if (!ins->input_ccc_handle && ins->input_value_handle
                    && handle > ins->input_value_handle) {
                    ins->input_ccc_handle = handle;
                }
            }
            else if (!uuid128 && info16[i].uuid == BT_UUID_GATT_CCC) {
                /* CCC descriptor in a 16-bit format response */
                if (!ins->input_ccc_handle && ins->input_value_handle
                    && handle > ins->input_value_handle) {
                    ins->input_ccc_handle = handle;
                }
            }
        }

        if (last_handle < ins->service_end) {
            bt_att_cmd_find_info_req(device->acl_handle, last_handle + 1, ins->service_end);
            return;
        }
    }

chars_done:
    if (ins->input_value_handle == 0) {
        printf("# Steam Triton: input characteristic missing, disconnecting\n");
        bt_mon_log(true, "# Steam Triton: input characteristic missing, disconnecting\n");
        bt_hci_disconnect(device);
        return;
    }

    printf("# Steam Triton: input handle %#x report=0x%02X report_chr=%#x rumble=%#x ccc=%#x\n",
        ins->input_value_handle, ins->report_id, ins->report_value_handle,
        ins->rumble_value_handle, ins->input_ccc_handle);
    bt_mon_log(true, "# Steam Triton: input handle %#x report=0x%02X report_chr=%#x rumble=%#x ccc=%#x\n",
        ins->input_value_handle, ins->report_id, ins->report_value_handle,
        ins->rumble_value_handle, ins->input_ccc_handle);

    device->hid_state = STEAM_STATE_FIND_CCC;
    bt_att_cmd_find_info_req(device->acl_handle, ins->input_value_handle + 1, ins->service_end);
}

static void steam_find_ccc_rsp(struct bt_dev *device, uint32_t att_len,
        uint8_t *info, uint32_t format) {
    struct steam_dev *ins = get_ins(device);
    struct bt_att_info_16 *info16 = NULL;
    struct bt_att_info_128 *info128 = NULL;
    uint32_t elem_cnt;
    uint16_t last_handle = 0;

    if (info) {
        if (format == BT_ATT_INFO_16) {
            info16 = (struct bt_att_info_16 *)info;
            elem_cnt = (att_len - 2) / sizeof(*info16);
            if (elem_cnt == 0) {
                goto ccc_done;
            }
            last_handle = info16[elem_cnt - 1].handle;
            for (uint32_t i = 0; i < elem_cnt; i++) {
                if (!ins->input_ccc_handle && info16[i].uuid == BT_UUID_GATT_CCC) {
                    ins->input_ccc_handle = info16[i].handle;
                    break;
                }
            }
        }
        else {
            info128 = (struct bt_att_info_128 *)info;
            elem_cnt = (att_len - 2) / sizeof(*info128);
            if (elem_cnt == 0) {
                goto ccc_done;
            }
            last_handle = info128[elem_cnt - 1].handle;
            for (uint32_t i = 0; i < elem_cnt; i++) {
                if (!ins->input_ccc_handle && *(uint16_t *)&info128[i].uuid[12] == 0x2902) {
                    ins->input_ccc_handle = info128[i].handle;
                    break;
                }
            }
        }

        if (last_handle < ins->service_end) {
            bt_att_cmd_find_info_req(device->acl_handle, last_handle + 1, ins->service_end);
            return;
        }
    }

ccc_done:
    if (ins->input_ccc_handle == 0) {
        printf("# Steam Triton: input CCC missing, disconnecting\n");
        bt_mon_log(true, "# Steam Triton: input CCC missing, disconnecting\n");
        bt_hci_disconnect(device);
        return;
    }

    device->hid_state = STEAM_STATE_EN_CCC;
    uint16_t ccc = BT_GATT_CCC_NOTIFY;
    bt_att_cmd_write_req(device->acl_handle, ins->input_ccc_handle, (uint8_t *)&ccc, sizeof(ccc));
}

static void steam_find_notify(struct bt_dev *device, uint16_t att_handle,
        uint8_t *data, uint32_t len) {
    struct steam_dev *ins = get_ins(device);
    uint8_t report[64];

    if (!ins->input_value_handle || att_handle != ins->input_value_handle) {
        return;
    }
    if (!len || len > sizeof(report) - 1) {
        return;
    }

    report[0] = ins->report_id ? ins->report_id : STEAM_TRITON_REPORT_STATE_BLE;
    memcpy(&report[1], data, len);
    bt_host_bridge(device, report[0], report, len + 1);
}

void bt_hid_steam_init(struct bt_dev *device) {
    struct steam_dev *ins = get_ins(device);

    /* Stop any leftover periodic timer from a previous connection */
    if (ins->timer_hdl) {
        esp_timer_stop(ins->timer_hdl);
        esp_timer_delete(ins->timer_hdl);
        ins->timer_hdl = NULL;
    }
    memset(ins, 0, sizeof(*ins));

    printf("# Steam Triton: Valve GATT setup (skip HOGP)\n");
    bt_mon_log(true, "# Steam Triton: Valve GATT setup (skip HOGP)\n");

    device->hid_state = STEAM_STATE_FIND_SVC;
    bt_att_cmd_read_group_req_uuid16(device->acl_handle, 0x0001, BT_UUID_GATT_PRIMARY);
}

void bt_hid_steam_hdlr(struct bt_dev *device, struct bt_hci_pkt *bt_hci_acl_pkt, uint32_t len) {
    uint32_t att_len = len - (BT_HCI_H4_HDR_SIZE + BT_HCI_ACL_HDR_SIZE + sizeof(struct bt_l2cap_hdr));

    switch (bt_hci_acl_pkt->att_hdr.code) {
        case BT_ATT_OP_ERROR_RSP:
            /* An ATT error response is non-fatal once we are streaming:
             * the Triton may reject a write or report an error on a stale
             * request, but notification/input reports keep flowing. Only
             * treat errors as end-of-walk during discovery, and never
             * disconnect a healthy link. */
            printf("# Steam Triton: ATT error st=%ld req=%02X h=%02X%02X err=%02X\n",
                device->hid_state, bt_hci_acl_pkt->att_data[0],
                bt_hci_acl_pkt->att_data[1], bt_hci_acl_pkt->att_data[2],
                bt_hci_acl_pkt->att_data[3]);
            bt_mon_log(true, "# Steam Triton: ATT error st=%ld req=%02X h=%02X%02X err=%02X\n",
                device->hid_state, bt_hci_acl_pkt->att_data[0],
                bt_hci_acl_pkt->att_data[1], bt_hci_acl_pkt->att_data[2],
                bt_hci_acl_pkt->att_data[3]);
            switch (device->hid_state) {
                case STEAM_STATE_FIND_SVC:
                    /* End of group walk */
                    steam_find_svc_rsp(device, att_len, NULL, 0);
                    break;
                case STEAM_STATE_FIND_CHARS:
                    /* End of info walk */
                    steam_find_chars_rsp(device, att_len, NULL, 0);
                    break;
                case STEAM_STATE_FIND_CCC:
                    /* End of info walk */
                    steam_find_ccc_rsp(device, att_len, NULL, 0);
                    break;
                case STEAM_STATE_EN_CCC:
                    /* CCC enable failed - can't get notifications; still
                     * mark ready so the link stays up. */
                    steam_on_ready(device);
                    break;
                default:
                    /* Keep the link alive: inputs already stream via NOTIFY */
                    if (!atomic_test_bit(&device->flags, BT_DEV_HID_INIT_DONE)) {
                        steam_on_ready(device);
                    }
                    break;
            }
            break;
        case BT_ATT_OP_READ_GROUP_RSP:
        {
            struct bt_att_read_group_rsp *read_group_rsp =
                (struct bt_att_read_group_rsp *)bt_hci_acl_pkt->att_data;
            if (device->hid_state == STEAM_STATE_FIND_SVC) {
                steam_find_svc_rsp(device, att_len, (uint8_t *)read_group_rsp->data,
                    read_group_rsp->len);
            }
            break;
        }
        case BT_ATT_OP_FIND_INFO_RSP:
        {
            struct bt_att_find_info_rsp *find_info_rsp =
                (struct bt_att_find_info_rsp *)bt_hci_acl_pkt->att_data;
            switch (device->hid_state) {
                case STEAM_STATE_FIND_CHARS:
                    steam_find_chars_rsp(device, att_len, find_info_rsp->info,
                        find_info_rsp->format);
                    break;
                case STEAM_STATE_FIND_CCC:
                    steam_find_ccc_rsp(device, att_len, find_info_rsp->info,
                        find_info_rsp->format);
                    break;
                default:
                    break;
            }
            break;
        }
        case BT_ATT_OP_WRITE_RSP:
            switch (device->hid_state) {
                case STEAM_STATE_EN_CCC:
                    printf("# Steam Triton: input notifications enabled\n");
                    steam_on_ready(device);
                    break;
                default:
                    break;
            }
            break;
        case BT_ATT_OP_NOTIFY:
        {
            struct bt_att_notify *notify = (struct bt_att_notify *)bt_hci_acl_pkt->att_data;
            steam_find_notify(device, notify->handle, notify->value,
                att_len - sizeof(notify->handle));
            break;
        }
        default:
            /* Fall back to the BlueRetro config GATT server handling */
            bt_att_cfg_hdlr(device, bt_hci_acl_pkt, len);
            break;
    }
}

void bt_hid_cmd_steam_out(struct bt_dev *device, void *report) {
    struct steam_dev *ins;
    uint8_t *out = (uint8_t *)report;
    uint8_t weak, strong, state;

    if (!device || !report) {
        return;
    }
    ins = get_ins(device);

    if (!ins->ready || (!ins->rumble_value_handle && !ins->report_value_handle)) {
        return;
    }

    weak = out[0];
    strong = out[1];
    state = out[2];

    if (state) {
        if (ins->rumble_weak != weak || ins->rumble_strong != strong
            || ins->rumble_ms_left == 0) {
            ins->rumble_pending = true;
        }
        ins->rumble_weak = weak;
        ins->rumble_strong = strong;
        /* Keep the ~40 ms resend alive while the console keeps rumbling */
        ins->rumble_ms_left = STEAM_RUMBLE_REARM_MS;
    }
    else if (ins->rumble_weak != 0 || ins->rumble_strong != 0 || ins->rumble_ms_left) {
        ins->rumble_weak = 0;
        ins->rumble_strong = 0;
        ins->rumble_ms_left = 0;
        ins->rumble_pending = true;
    }

    if (ins->rumble_pending) {
        steam_send_rumble(device, ins->rumble_weak, ins->rumble_strong);
        ins->rumble_pending = false;
    }
}
