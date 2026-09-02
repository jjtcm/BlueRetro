/*
 * Copyright (c) 2026, jjtcm
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _BT_HIDP_STEAM_H_
#define _BT_HIDP_STEAM_H_

#include "hidp.h"

/* Valve / Triton device identifiers */
#define STEAM_VID 0x28de

#define STEAM_TRITON_PID_USB 0x1302 /* Body USB */
#define STEAM_TRITON_PID_BLE 0x1303 /* Body BLE */
#define STEAM_TRITON_PID_PUCK 0x1304 /* Valve RF puck */
#define STEAM_TRITON_PID_NEREID 0x1305 /* Related PID */

/* Triton report IDs (same as SDL controller_structs.h) */
#define STEAM_TRITON_REPORT_STATE 0x42 /* Controller State (USB) */
#define STEAM_TRITON_REPORT_BATTERY 0x43 /* Battery Status */
#define STEAM_TRITON_REPORT_STATE_BLE 0x45 /* Controller State BLE */
#define STEAM_TRITON_REPORT_STATE_TS 0x47 /* Controller State w/ timestamp */

/* Triton output report IDs */
#define STEAM_TRITON_OUT_REPORT_RUMBLE 0x80 /* MsgHapticRumble */

/* Valve 128-bit UUID family "100F6C32-1735-4313-B402-38567131E5F3".
 * Over the air (LSB first) the family distinctive byte is at byte 12:
 *   F3 E5 31 71 56 38 02 B4 13 43 35 17 XX 6C 0F 10
 * where XX is the suffix byte below. */
#define STEAM_SVC_SUFFIX 0x32 /* Valve service itself */
#define STEAM_CHR_INPUT_STATE 0x7A /* Input report 0x45 */
#define STEAM_CHR_INPUT_STATE_TS 0x7C /* Input report 0x47 */
#define STEAM_CHR_REPORT 0x34 /* Report write (lizard-off) */
#define STEAM_CHR_RUMBLE 0xB5 /* Rumble write (out report 0x80) */

/* Triton button bits (SDL TritonButtons) */
#define STEAM_BTN_A 0x00000001u
#define STEAM_BTN_B 0x00000002u
#define STEAM_BTN_X 0x00000004u
#define STEAM_BTN_Y 0x00000008u
#define STEAM_BTN_QAM 0x00000010u
#define STEAM_BTN_R3 0x00000020u
#define STEAM_BTN_VIEW 0x00000040u
#define STEAM_BTN_R4 0x00000080u
#define STEAM_BTN_R5 0x00000100u
#define STEAM_BTN_RB 0x00000200u
#define STEAM_BTN_DPAD_DOWN 0x00000400u
#define STEAM_BTN_DPAD_RIGHT 0x00000800u
#define STEAM_BTN_DPAD_LEFT 0x00001000u
#define STEAM_BTN_DPAD_UP 0x00002000u
#define STEAM_BTN_MENU 0x00004000u
#define STEAM_BTN_L3 0x00008000u
#define STEAM_BTN_STEAM 0x00010000u
#define STEAM_BTN_L4 0x00020000u
#define STEAM_BTN_L5 0x00040000u
#define STEAM_BTN_LB 0x00080000u
#define STEAM_BTN_RPAD_CLICK 0x00400000u
#define STEAM_BTN_LPAD_CLICK 0x04000000u

struct bt_dev;
struct bt_hci_pkt;

void bt_hid_steam_init(struct bt_dev *device);
void bt_hid_steam_hdlr(struct bt_dev *device, struct bt_hci_pkt *bt_hci_acl_pkt, uint32_t len);
void bt_hid_cmd_steam_out(struct bt_dev *device, void *report);

#endif /* _BT_HIDP_STEAM_H_ */
