/*
 * Copyright (c) 2026, jjtcm
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _WIRELESS_STEAM_H_
#define _WIRELESS_STEAM_H_

#include "adapter/adapter.h"

int32_t steam_to_generic(struct bt_data *bt_data, struct wireless_ctrl *ctrl_data);
bool steam_fb_from_generic(struct generic_fb *fb_data, struct bt_data *bt_data);

#endif /* _WIRELESS_STEAM_H_ */
