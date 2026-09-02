#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 jjtcm
# SPDX-License-Identifier: Apache-2.0
"""
br_trace.py - Decode BlueRetro BT debug traces.

BlueRetro can record a low-level Bluetooth HCI trace to its memory-card debug
buffer. The buffer is a raw concatenation of bt_mon_tx() records
(see main/bluetooth/mon.c and main/adapter/memory_card.c).

This tool decodes that dump into human-readable HCI / L2CAP / SMP / ATT /
GATT events and the BlueRetro `#` serial log lines recorded as SYSTEM_NOTE
records. It also reassembles fragmented L2CAP packets (like the Valve GATT
exchanges where a peer splits a large PDU across multiple ACL packets), which
is required to follow a Steam Controller 2026 (Triton) pairing and input
session.

Usage
-----
    python3 tools/br_trace.py br_debug_trace.bin --smp --att --notes

Options:
    --cmds      show HCI commands
    --events    show HCI events
    --att       show ATT (GATT) packets
    --smp       show Security Manager Protocol packets (pairing / secure connections)
    --notes     show the BlueRetro serial `#` log lines
    --cont      show L2CAP fragmentation / continuation records
    --all       show everything
    --addr A    only show packets for a peer bdaddr (XX:XX:XX:XX:XX:XX)

Examples
--------
    # Follow a full STEAM (Valve GATT) pairing + input session:
    python3 tools/br_trace.py br_debug_trace.bin --smp --att --notes | grep -i steam

    # Look at the ATT/GATT discovery of the Valve service (100F6C32-...):
    python3 tools/br_trace.py br_debug_trace.bin --att

    # See fragmented L2CAP packets (e.g. a peer's 65-byte SMP Public Key):
    python3 tools/br_trace.py br_debug_trace.bin --cont --smp

Notes
-----
* The record framing is the btmon "tty/dbus" 11-byte header used by
  tools/btmon_btsnoop*.py, but the dump has no btsnoop file header.
* SYSTEM_NOTE (opcode 12) and USER_LOGGING (13) records carry the BlueRetro
  `#` console log lines that are also echoed on the UART.
"""

import argparse
import struct
import sys

# ---------------------------------------------------------------------------
# btmon opcodes (same namespace as tools/btmon_btsnoop*.py)
# ---------------------------------------------------------------------------
OP = {
    0:  "NEW_INDEX",
    1:  "DEL_INDEX",
    2:  "CMD_TX",
    3:  "EVT_RX",
    4:  "ACL_TX",
    5:  "ACL_RX",
    6:  "SCO_TX",
    7:  "SCO_RX",
    8:  "OPEN_INDEX",
    9:  "CLOSE_INDEX",
    10: "INDEX_INFO",
    11: "VENDOR_DIAG",
    12: "SYSTEM_NOTE",
    13: "USER_LOGGING",
}

# ---------------------------------------------------------------------------
# HCI helpers
# ---------------------------------------------------------------------------
HCI_OGF_LE = 0x08


def hci_op_name(opcode):
    ogf = (opcode >> 10) & 0x3F
    ocf = opcode & 0x3FF
    if ogf == HCI_OGF_LE:
        le = {
            0x0001: "LE_SET_EVENT_MASK",
            0x0002: "LE_READ_BUFFER_SIZE",
            0x0003: "LE_READ_LOCAL_FEATURES",
            0x0005: "LE_SET_RANDOM_ADDRESS",
            0x0006: "LE_SET_ADV_PARAM",
            0x0008: "LE_SET_ADV_DATA",
            0x0009: "LE_SET_SCAN_RSP_DATA",
            0x000A: "LE_SET_ADV_ENABLE",
            0x000B: "LE_SET_SCAN_PARAM",
            0x000C: "LE_SET_SCAN_ENABLE",
            0x000D: "LE_CREATE_CONN",
            0x0010: "LE_CONN_UPDATE",
            0x0011: "LE_READ_REMOTE_FEATURES",
            0x0012: "LE_ADD_DEV_TO_WL",
            0x0013: "LE_REM_DEV_FROM_WL",
            0x0018: "LE_START_ENC",
            0x0025: "LE_P256_PUBLIC_KEY",
            0x0026: "LE_GENERATE_DHKEY",
        }
        return le.get(ocf, "LE_0x%04X" % ocf)
    return "0x%04X" % opcode


LE_SUB = {
    1: "ADV",
    2: "DIR_ADV",
    3: "SCAN",
    4: "SCAN_RSP",
    5: "CONN_CMPL",
    6: "ADV_TX",
    7: "P256_CMPL",
    8: "CONN_UPD_CMPL",
    9: "DHKEY_CMPL",
    13: "ENH_CONN",
}

# ---------------------------------------------------------------------------
# L2CAP / SMP / ATT
# ---------------------------------------------------------------------------
L2CAP_CID_ATT = 0x0004
L2CAP_CID_LE_SIG = 0x0005
L2CAP_CID_SMP = 0x0006

SMP = {
    1: "PAIR_REQ",
    2: "PAIR_RSP",
    3: "CONFIRM",
    4: "RANDOM",
    5: "FAIL",
    6: "ENC_INFO",
    7: "MASTER_ID",
    8: "IDENT",
    9: "ADDR",
    10: "SIGN",
    11: "SEC_REQ",
    12: "PUB_KEY",
    13: "DHKEY_CHK",
    14: "KEYPRESS",
}

ATT = {
    1: "ERROR_RSP",
    2: "MTU_REQ",
    3: "MTU_RSP",
    4: "FIND_INFO",
    5: "FIND_INFO_RSP",
    6: "FIND_TYPE",
    8: "READ_TYPE",
    9: "READ_TYPE_RSP",
    10: "READ_REQ",
    11: "READ_RSP",
    12: "READ_BLOB",
    13: "READ_BLOB_RSP",
    16: "READ_GROUP",
    17: "READ_GROUP_RSP",
    18: "WRITE_REQ",
    19: "WRITE_RSP",
    27: "NOTIFY",
    28: "INDICATE",
    82: "WRITE_CMD",
}


def fmt_addr(b, n=6):
    return ":".join("%02X" % x for x in b[:n])


# ---------------------------------------------------------------------------
# Record reader
# ---------------------------------------------------------------------------
def read_records(data):
    """Yield (idx, opcode, payload, timestamp) for each record."""
    off = 0
    idx = 0
    while off + 11 <= len(data):
        data_len, opcode, flags, hdr_len, ts_type, ts_data = struct.unpack(
            "<HHBBBI", data[off:off + 11]
        )
        body_len = data_len - hdr_len - 4  # drop ts_data(4) + 5-byte prefix = 9
        if body_len < 0 or off + 11 + body_len > len(data):
            break
        payload = data[off + 11: off + 11 + body_len]
        yield idx, opcode, payload, ts_data
        off += 11 + body_len
        idx += 1


# ---------------------------------------------------------------------------
# SMP / ATT decoders
# ---------------------------------------------------------------------------
def decode_smp(d):
    if not d:
        return None
    code = d[0]
    name = SMP.get(code, "0x%02X" % code)
    parts = [name]
    if code == 5 and len(d) > 1:
        parts.append("reason=0x%02X" % d[1])
    elif code == 12 and len(d) >= 65:
        parts.append("x=%s.." % d[1:9].hex())
    elif code in (3, 4, 13) and len(d) > 1:
        parts.append(d[1:17].hex())
    elif code in (1, 2) and len(d) >= 6:
        parts.append("io=%02X oob=%02X auth=%02X keys=%02X%02X" % (
            d[1], d[2], d[3], d[4], d[5]))
    elif code == 6 and len(d) > 1:
        parts.append(d[1:17].hex())
    return "SMP: %s" % " ".join(parts)


def decode_att(d):
    if not d:
        return None
    code = d[0]
    name = ATT.get(code, "0x%02X" % code)
    parts = [name]
    if code in (10, 12, 14, 16, 18, 2, 8) and len(d) >= 3:
        parts.append("h=0x%04X" % struct.unpack("<H", d[1:3])[0])
    elif code == 27 and len(d) > 3:
        parts.append("handle=0x%04X val=%s" % (
            struct.unpack("<H", d[1:3])[0], d[3:19].hex()))
    elif code == 1 and len(d) >= 5:
        parts.append("req=%02X h=0x%04X err=0x%02X" % (
            d[1], struct.unpack("<H", d[2:4])[0], d[4]))
    elif code == 11 and len(d) > 1:
        parts.append(d[1:19].hex())
    return "ATT: %s" % " ".join(parts)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Decode BlueRetro BT debug traces")
    ap.add_argument("file", help="raw memory-card debug trace (br_debug_trace.bin)")
    ap.add_argument("--cmds", action="store_true")
    ap.add_argument("--events", action="store_true")
    ap.add_argument("--att", action="store_true")
    ap.add_argument("--smp", action="store_true")
    ap.add_argument("--notes", action="store_true")
    ap.add_argument("--cont", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--addr", default="", help="filter by peer bdaddr")
    args = ap.parse_args()

    try:
        data = open(args.file, "rb").read()
    except OSError as e:
        print("error: %s" % e)
        return 1

    if not any([args.cmds, args.events, args.att, args.smp, args.notes,
                args.cont]) and not args.all:
        args.all = True

    frag_buf = bytearray()
    frag_size = 0

    for idx, opcode, payload, ts in read_records(data):
        # Notes (BlueRetro serial logs)
        if opcode in (12, 13):
            if args.notes or args.all:
                txt = payload.decode("utf-8", "replace").rstrip("\n")
                txt = "".join(ch if ch.isprintable() or ch == "\n" else "." for ch in txt)
                print("[%04d] NOTE: %s" % (idx, txt))
            continue

        # BlueRetro strips the H4 type byte, so payload is the raw HCI frame
        body = payload

        if opcode == 2:  # HCI command
            if args.cmds or args.all:
                if len(body) >= 4:
                    opc = struct.unpack("<H", body[0:2])[0]
                    print("[%04d] TX CMD %s %s" % (idx, hci_op_name(opc), body[4:].hex()))
                else:
                    print("[%04d] TX CMD short %s" % (idx, body.hex()))
            continue

        if opcode == 3:  # HCI event
            if not body:
                continue
            ev = body[0]
            if ev == 0x3E:  # LE meta
                if len(body) > 2:
                    sub = body[2]
                    if args.events or args.all:
                        extra = ""
                        if sub == 1 and len(body) >= 15:
                            extra = "addr=%s" % fmt_addr(body[9:15])
                        print("[%04d] EVT LE %s %s" % (idx, LE_SUB.get(sub, "SUB%02X" % sub), extra))
                continue
            if args.events or args.all:
                if ev == 0x0E and len(body) > 4:  # command complete
                    print("[%04d] EVT CMD_COMPLETE %s" % (idx, hci_op_name(struct.unpack("<H", body[3:5])[0])))
                else:
                    print("[%04d] EVT code=0x%02X %s" % (idx, ev, body[1:].hex()))
            continue

        if opcode in (4, 5):  # ACL
            direction = "TX" if opcode == 4 else "RX"
            if len(body) < 4:
                continue
            acl_handle = struct.unpack("<H", body[0:2])[0]
            acl_flags = (acl_handle >> 12) & 0x3
            acl_len = struct.unpack("<H", body[2:4])[0]
            acl_data = body[4:4 + acl_len]

            l2len = 0
            cid = 0
            l2data = b""

            if acl_flags == 1:  # CONT
                if frag_size == 0:
                    l2data = acl_data
                else:
                    frag_buf.extend(acl_data)
                    if len(frag_buf) < frag_size:
                        if args.cont or args.all:
                            print("[%04d] %s ACL CONT (waiting, %d/%d)" % (idx, direction, len(frag_buf), frag_size))
                        continue
                    complete = bytes(frag_buf[:frag_size])
                    frag_buf = bytearray()
                    if len(complete) < 4:
                        continue
                    l2len = struct.unpack("<H", complete[0:2])[0]
                    cid = struct.unpack("<H", complete[2:4])[0]
                    l2data = complete[4:]
                    if args.cont or args.all:
                        print("[%04d] %s ACL CONT reassembled cid=0x%04X len=%d" % (idx, direction, cid, l2len))
            elif acl_flags == 2 and len(acl_data) >= 4:  # START / fragmented
                l2len = struct.unpack("<H", acl_data[0:2])[0]
                cid = struct.unpack("<H", acl_data[2:4])[0]
                l2data = acl_data[4:]
                if len(l2data) < l2len:
                    frag_buf = bytearray(acl_data)
                    frag_size = l2len + 4
                    if args.cont or args.all:
                        print("[%04d] %s ACL START frag (l2len=%d got %d)" % (idx, direction, l2len, len(l2data)))
                    continue
            else:  # single / complete
                if len(acl_data) < 4:
                    continue
                l2len = struct.unpack("<H", acl_data[0:2])[0]
                cid = struct.unpack("<H", acl_data[2:4])[0]
                l2data = acl_data[4:4 + l2len]

            if cid == L2CAP_CID_SMP and (args.smp or args.all):
                dmsg = decode_smp(l2data)
                if dmsg:
                    print("[%04d] %s %s" % (idx, direction, dmsg))
            elif cid == L2CAP_CID_ATT and (args.att or args.all):
                dmsg = decode_att(l2data)
                if dmsg:
                    print("[%04d] %s %s" % (idx, direction, dmsg))
            elif (args.cont or args.all) and cid == L2CAP_CID_LE_SIG:
                print("[%04d] %s L2CAP cid=0x%04X %s" % (idx, direction, cid, l2data[:8].hex()))
            continue

        if args.notes or args.all:
            print("[%04d] %s len=%d" % (idx, OP.get(opcode, opcode), len(payload)))

    return 0


if __name__ == "__main__":
    sys.exit(main())
