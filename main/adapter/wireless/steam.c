/*
 * Copyright (c) 2026, jjtcm
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include "zephyr/types.h"
#include "tools/util.h"
#include "adapter/config.h"
#include "adapter/mapping_quirks.h"
#include "bluetooth/hidp/steam.h"
#include "bluetooth/mon.h"
#include "tests/cmds.h"
#include "steam.h"

/* Steam Controller 2026 (Triton) state report (report ID 0x42/0x45/0x47).
 * First bytes decoded here (SDL TritonMTUNoQuat_t):
 *   0: report ID
 *   1: seq
 *   2-5: buttons (u32 LE)
 *   6-7: LT (i16 LE, 0 = released, ~32767 = full)
 *   8-9: RT (i16 LE)
 *   10-11: LX (i16 LE, + = right)
 *   12-13: LY (i16 LE, + = down)
 *   14-15: RX (i16 LE, + = right)
 *   16-17: RY (i16 LE, + = down)
 */
struct steam_map {
    uint8_t report_id;
    uint8_t seq;
    uint32_t buttons;
    int16_t lt;
    int16_t rt;
    int16_t lx;
    int16_t ly;
    int16_t rx;
    int16_t ry;
} __packed;

static const struct ctrl_meta steam_axes_meta[ADAPTER_MAX_AXES] =
{
    {.neutral = 0, .abs_max = 32767, .abs_min = 32767},
    {.neutral = 0, .abs_max = 32767, .abs_min = 32767, .polarity = 1},
    {.neutral = 0, .abs_max = 32767, .abs_min = 32767},
    {.neutral = 0, .abs_max = 32767, .abs_min = 32767, .polarity = 1},
    {.neutral = 0, .abs_max = 32767, .abs_min = 0},
    {.neutral = 0, .abs_max = 32767, .abs_min = 0},
};

static const uint32_t steam_mask[4] = {
    BIT(PAD_LX_LEFT) | BIT(PAD_LX_RIGHT) | BIT(PAD_LY_DOWN) | BIT(PAD_LY_UP) |
    BIT(PAD_RX_LEFT) | BIT(PAD_RX_RIGHT) | BIT(PAD_RY_DOWN) | BIT(PAD_RY_UP) |
    BIT(PAD_LD_LEFT) | BIT(PAD_LD_RIGHT) | BIT(PAD_LD_DOWN) | BIT(PAD_LD_UP) |
    BIT(PAD_RB_LEFT) | BIT(PAD_RB_RIGHT) | BIT(PAD_RB_DOWN) | BIT(PAD_RB_UP) |
    BIT(PAD_MM) | BIT(PAD_MS) | BIT(PAD_MT) |
    BIT(PAD_LM) | BIT(PAD_LS) | /* L2 + L1 (LB) */
    BIT(PAD_RM) | BIT(PAD_RS) | /* R2 + R1 (RB) */
    BIT(PAD_LJ) | BIT(PAD_RJ),
    0, 0, 0
};

static const uint32_t steam_desc[4] = {
    BIT(PAD_LX_LEFT) | BIT(PAD_LX_RIGHT) | BIT(PAD_LY_DOWN) | BIT(PAD_LY_UP) |
    BIT(PAD_RX_LEFT) | BIT(PAD_RX_RIGHT) | BIT(PAD_RY_DOWN) | BIT(PAD_RY_UP) |
    BIT(PAD_LM) | BIT(PAD_RM), /* Analog triggers are axes */
    0, 0, 0
};

/* Generic index i -> Triton button bits for generic_btns_mask[i]
 * (values are raw Triton button masks, not bit indices) */
static const uint32_t steam_btns_mask[32] = {
    0, 0, 0, 0,
    0, 0, 0, 0,
    STEAM_BTN_DPAD_LEFT, STEAM_BTN_DPAD_RIGHT, STEAM_BTN_DPAD_DOWN, STEAM_BTN_DPAD_UP,
    0, 0, 0, 0,
    STEAM_BTN_X, STEAM_BTN_B, STEAM_BTN_A, STEAM_BTN_Y,
    STEAM_BTN_VIEW, STEAM_BTN_MENU, STEAM_BTN_STEAM | STEAM_BTN_QAM, 0,
    0, STEAM_BTN_LB, 0, STEAM_BTN_L3 | STEAM_BTN_LPAD_CLICK,
    0, STEAM_BTN_RB, 0, STEAM_BTN_R3 | STEAM_BTN_RPAD_CLICK,
};

static int32_t steam_pad_init(struct bt_data *bt_data) {
    struct ctrl_meta *meta = bt_data->raw_src_mappings[PAD].meta;

    mapping_quirks_apply(bt_data);

    memcpy(meta, steam_axes_meta, sizeof(steam_axes_meta));
    memcpy(bt_data->raw_src_mappings[PAD].btns_mask, steam_btns_mask,
        sizeof(bt_data->raw_src_mappings[PAD].btns_mask));

    for (uint32_t i = 0; i < ADAPTER_MAX_AXES; i++) {
        bt_data->base.axes_cal[i] = 0;
    }

    atomic_set_bit(&bt_data->base.flags[PAD], BT_INIT);
    return 0;
}

int32_t steam_to_generic(struct bt_data *bt_data, struct wireless_ctrl *ctrl_data) {
    struct steam_map *map = (struct steam_map *)bt_data->base.input;
    struct ctrl_meta *meta = bt_data->raw_src_mappings[PAD].meta;

    /* Need report ID + seq + buttons + 2 triggers + 4 stick axes (18 bytes) */
    if (bt_data->base.input_len < 18 || map->report_id == 0) {
        return -1;
    }

    if (!atomic_test_bit(&bt_data->base.flags[PAD], BT_INIT)) {
        if (steam_pad_init(bt_data)) {
            return -1;
        }
    }

    memset((void *)ctrl_data, 0, sizeof(*ctrl_data));

    ctrl_data->mask = (uint32_t *)steam_mask;
    ctrl_data->desc = (uint32_t *)steam_desc;

    ///* Debug: dump the raw Triton button dword so button bits can be verified
    // * on hardware (e.g. LB=0x00080000, RB=0x00000200). */
    //static uint32_t last_btns = 0xFFFFFFFF;
    //if (map->buttons != last_btns) {
    //    printf("# Steam btn=0x%08lX\n", (unsigned long)map->buttons);
    //    last_btns = map->buttons;
    //}

    for (uint32_t i = 0; i < ARRAY_SIZE(generic_btns_mask); i++) {
        if (map->buttons & steam_btns_mask[i]) {
            ctrl_data->btns[0].value |= generic_btns_mask[i];
        }
    }

    int32_t axes[6];
    axes[0] = map->lx;
    /* Triton Y is + = up; BlueRetro Y convention is + = down (like PS4).
     * Negate so pushing up gives a negative LY value (polarity=1 maps that
     * to the up direction). */
    axes[1] = -map->ly;
    axes[2] = map->rx;
    axes[3] = -map->ry;
    axes[4] = map->lt;
    axes[5] = map->rt;
    if (axes[4] < 0) {
        axes[4] = 0;
    }
    if (axes[5] < 0) {
        axes[5] = 0;
    }

    TESTS_CMDS_LOG("\"wireless_input\": {\"report_id\": %lu, \"axes\": [%d, %d, %d, %d, %d, %d], \"btns\": %lu},\n",
        bt_data->base.report_id, axes[0], axes[1], axes[2], axes[3], axes[4], axes[5], map->buttons);

    for (uint32_t i = 0; i < ADAPTER_MAX_AXES; i++) {
        ctrl_data->axes[i].meta = &meta[i];
        ctrl_data->axes[i].value = axes[i] - meta[i].neutral;
    }

    return 0;
}

bool steam_fb_from_generic(struct generic_fb *fb_data, struct bt_data *bt_data) {
    switch (fb_data->type) {
        case FB_TYPE_RUMBLE:
            /* weak (right) / strong (left) magnitudes + on/off state,
             * consumed by bt_hid_cmd_steam_out */
            bt_data->base.output[0] = (uint8_t)fb_data->hf_pwr;
            bt_data->base.output[1] = (uint8_t)fb_data->lf_pwr;
            bt_data->base.output[2] = fb_data->state ? 1 : 0;
            break;
        default:
            break;
    }
    return true;
}
