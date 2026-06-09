"""
twist_protocol.py — wire-format codec for the Teleop Dashboard.

Mirrors webtransport_bidi/modules/protocol.js and modules/codec.js exactly so
the browser and Python sides agree on bytes.

  Binary frames (little-endian, CRC-8/SMBUS trailer):
    0x01 Twist     [type(1) | msgId(8) | t1(8) | mask(1) | N×float64 | crc(1)]
                   mask bit 7 = float32 instead of float64
    0x02 Ack       [type(1) | msgId(8) | t3(8) | t4(8) | dec(4) | proc(4) | enc(4) | crc(1)]  = 38B
    0x03 SyncReq   [type(1) | t1(8) | crc(1)]                                                 = 10B
    0x04 SyncResp  [type(1) | t1(8) | t2(8) | t3(8) | crc(1)]                                 = 26B

  JSON envelopes (UTF-8 text):
    Twist     {"t":1,"id","t1","mask","v":{"linear_y":..., ...}}
    Ack       {"t":2,"id","t1","t3","t4","dec","proc","enc"}
    SyncReq   {"t":3,"t1"}
    SyncResp  {"t":4,"t1","t2","t3"}
"""

from __future__ import annotations

import json
import struct
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple

# ── Message type bytes ────────────────────────────────────────────────────────
MSG_TWIST     = 0x01
MSG_ACK       = 0x02
MSG_SYNC_REQ  = 0x03
MSG_SYNC_RESP = 0x04

# ── Field mask bits ───────────────────────────────────────────────────────────
FIELD_LINEAR_X  = 0x01
FIELD_LINEAR_Y  = 0x02
FIELD_LINEAR_Z  = 0x04
FIELD_ANGULAR_X = 0x08
FIELD_ANGULAR_Y = 0x10
FIELD_ANGULAR_Z = 0x20
FIELD_ALL       = 0x3F

FIELD_HALF_PRECISION = 0x80
FIELD_MASK_BITS      = 0x3F

# Order MUST match modules/protocol.js FIELD_ORDER.
FIELD_NAMES = ("linear_x", "linear_y", "linear_z",
               "angular_x", "angular_y", "angular_z")
FIELD_BITS  = (FIELD_LINEAR_X, FIELD_LINEAR_Y, FIELD_LINEAR_Z,
               FIELD_ANGULAR_X, FIELD_ANGULAR_Y, FIELD_ANGULAR_Z)

# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class Twist:
    msg_id:         int
    t1:             int          # browser send ms (epoch)
    mask:           int          # low-6-bit selector
    half_precision: bool
    fmt:            str          # 'binary' | 'json'
    linear_x:       float = 0.0
    linear_y:       float = 0.0
    linear_z:       float = 0.0
    angular_x:      float = 0.0
    angular_y:      float = 0.0
    angular_z:      float = 0.0

    def selected_fields(self) -> list[Tuple[str, float]]:
        out = []
        for name, bit in zip(FIELD_NAMES, FIELD_BITS):
            if self.mask & bit:
                out.append((name, getattr(self, name)))
        return out


@dataclass
class SyncReq:
    t1:  int
    fmt: str


# ── CRC-8/SMBUS ───────────────────────────────────────────────────────────────
# Polynomial 0x07, init 0x00, no reflection.  Test vector: crc8(b"123456789") == 0xF4.

def crc8(buf: bytes) -> int:
    crc = 0
    for b in buf:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if (crc & 0x80) else (crc << 1) & 0xFF
    return crc


# ── Format sniffing ───────────────────────────────────────────────────────────

def peek_format(data: bytes) -> str:
    """Return 'binary' or 'json' based on the first byte."""
    if not data:
        return "binary"
    b = data[0]
    if b in (MSG_TWIST, MSG_ACK, MSG_SYNC_REQ, MSG_SYNC_RESP):
        return "binary"
    if b in (0x7B, 0x5B):  # '{' or '['
        return "json"
    return "binary"


def peek_type(data: bytes) -> int:
    """Return message type byte, or -1 if unknown."""
    fmt = peek_format(data)
    if fmt == "binary":
        return data[0] if data else -1
    try:
        return int(json.loads(data.decode("utf-8")).get("t", -1))
    except Exception:
        return -1


# ── Decoders (browser → python) ───────────────────────────────────────────────

def decode_twist(data: bytes) -> Optional[Twist]:
    fmt = peek_format(data)
    if fmt == "json":
        try:
            o = json.loads(data.decode("utf-8"))
        except Exception:
            return None
        if int(o.get("t", 0)) != MSG_TWIST:
            return None
        mask = int(o.get("mask", 0)) & FIELD_MASK_BITS
        v = o.get("v", {}) or {}
        twist = Twist(
            msg_id=int(o["id"]), t1=int(o["t1"]),
            mask=mask, half_precision=False, fmt="json",
        )
        for name in FIELD_NAMES:
            if name in v:
                setattr(twist, name, float(v[name]))
        return twist

    # Binary
    if len(data) < 19 or data[0] != MSG_TWIST:
        return None
    if crc8(data[:-1]) != data[-1]:
        return None
    msg_id, t1 = struct.unpack_from("<QQ", data, 1)
    wire_mask = data[17]
    mask = wire_mask & FIELD_MASK_BITS
    half = bool(wire_mask & FIELD_HALF_PRECISION)
    twist = Twist(
        msg_id=msg_id, t1=t1, mask=mask,
        half_precision=half, fmt="binary",
    )
    field_size = 4 if half else 8
    fmt_char   = "<f" if half else "<d"
    offset = 18
    for name, bit in zip(FIELD_NAMES, FIELD_BITS):
        if mask & bit:
            if offset + field_size > len(data) - 1:
                return None
            (val,) = struct.unpack_from(fmt_char, data, offset)
            setattr(twist, name, val)
            offset += field_size
    return twist


def decode_sync_req(data: bytes) -> Optional[SyncReq]:
    fmt = peek_format(data)
    if fmt == "json":
        try:
            o = json.loads(data.decode("utf-8"))
        except Exception:
            return None
        if int(o.get("t", 0)) != MSG_SYNC_REQ:
            return None
        return SyncReq(t1=int(o["t1"]), fmt="json")

    if len(data) < 10 or data[0] != MSG_SYNC_REQ:
        return None
    if crc8(data[:-1]) != data[-1]:
        return None
    (t1,) = struct.unpack_from("<Q", data, 1)
    return SyncReq(t1=t1, fmt="binary")


# ── Encoders (python → browser) ───────────────────────────────────────────────

def encode_ack(fmt: str, *, msg_id: int, t1: int, t3: int, t4: int,
               decode_us: int, process_us: int, encode_us: int) -> bytes:
    if fmt == "json":
        return json.dumps({
            "t": MSG_ACK, "id": msg_id, "t1": t1, "t3": t3, "t4": t4,
            "dec": int(decode_us), "proc": int(process_us), "enc": int(encode_us),
        }).encode("utf-8")
    # Binary: [type(1) | msgId(8) | t3(8) | t4(8) | dec(4) | proc(4) | enc(4) | crc(1)]
    body = struct.pack("<BQQQIII",
                       MSG_ACK, msg_id, t3, t4,
                       int(decode_us) & 0xFFFFFFFF,
                       int(process_us) & 0xFFFFFFFF,
                       int(encode_us) & 0xFFFFFFFF)
    return body + bytes((crc8(body),))


def encode_sync_resp(fmt: str, *, t1: int, t2: int, t3: int) -> bytes:
    if fmt == "json":
        return json.dumps({
            "t": MSG_SYNC_RESP, "t1": t1, "t2": t2, "t3": t3,
        }).encode("utf-8")
    body = struct.pack("<BQQQ", MSG_SYNC_RESP, t1, t2, t3)
    return body + bytes((crc8(body),))


# ── Time helpers ──────────────────────────────────────────────────────────────

def now_ms() -> int:
    """Wall-clock milliseconds since the Unix epoch (matches browser t1 / t6)."""
    return int(time.time() * 1000)


def perf_us() -> int:
    """Monotonic microseconds; used for decode_us / process_us / encode_us."""
    return int(time.perf_counter() * 1_000_000)
