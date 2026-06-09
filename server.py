#!/usr/bin/env python3
"""
WebTransport teleop server (aioquic).

Speaks the Twist / Ack / SyncReq / SyncResp protocol expected by the dashboard
frontend in this folder (see twist_protocol.py for wire format).

Endpoint:
  https://<host>:8443/wt?role=browser    twist source — gets Ack + SyncResp back
  https://<host>:8443/wt?role=observer   read-only sink — receives every twist
                                          the server processes (as datagram)

Both binary CRC-8 frames and JSON envelopes are accepted; the server replies in
the same format that the message arrived in.

Usage:
  python3 server.py --cert ../webtransport/cert_ec.pem \\
                    --key  ../webtransport/key_ec.pem
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from typing import Dict, Optional, Set
from urllib.parse import parse_qs, urlsplit

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    H3Event,
    HeadersReceived,
    WebTransportStreamDataReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent, StreamReset

from twist_protocol import (
    MSG_TWIST, MSG_SYNC_REQ,
    decode_twist, decode_sync_req,
    encode_ack, encode_sync_resp,
    now_ms, perf_us, peek_type,
)

BIND_ADDRESS = "::"
BIND_PORT = 8443

logger = logging.getLogger("wt-teleop")

# All currently connected sessions, keyed by role.
BROWSERS:  Set["WTSession"] = set()
OBSERVERS: Set["WTSession"] = set()


class WTSession:
    """One WebTransport session. The role decides how datagrams are handled."""

    def __init__(self, session_id: int, http: H3Connection,
                 protocol: "WebTransportProtocol", role: str, peer_label: str):
        self._session_id = session_id
        self._http = http
        self._protocol = protocol
        self._role = role
        self._label = peer_label

    @property
    def role(self) -> str:        return self._role
    @property
    def label(self) -> str:       return self._label
    @property
    def session_id(self) -> int:  return self._session_id

    def send_datagram(self, payload: bytes) -> None:
        try:
            self._http.send_datagram(self._session_id, payload)
            # Each H3Connection is bound to its own QuicConnection, and aioquic
            # only auto-flushes the connection whose event handler is currently
            # running. When we fan-out from a browser handler to N observer
            # sessions, every observer needs its own explicit transmit() or the
            # datagram sits in the send buffer until the next inbound packet.
            self._protocol.transmit()
        except Exception as e:
            logger.debug("send to %s failed: %s", self._label, e)

    def h3_event_received(self, event: H3Event) -> None:
        if isinstance(event, DatagramReceived):
            self._on_datagram(bytes(event.data))
        elif isinstance(event, WebTransportStreamDataReceived):
            # The dashboard doesn't open WT streams; ignore but don't crash.
            pass

    def _on_datagram(self, data: bytes) -> None:
        if self._role != "browser":
            logger.debug("dropping inbound datagram from %s (role=%s)",
                         self._label, self._role)
            return

        mtype = peek_type(data)
        if mtype == MSG_TWIST:
            self._handle_twist(data)
        elif mtype == MSG_SYNC_REQ:
            self._handle_sync(data)
        else:
            logger.warning("unknown msg type %s from %s (%dB)",
                           mtype, self._label, len(data))

    def _handle_twist(self, data: bytes) -> None:
        t3 = now_ms()                       # wall-clock receive
        dec_start = perf_us()
        twist = decode_twist(data)
        decode_us = perf_us() - dec_start
        if twist is None:
            logger.warning("twist decode failed (%dB) from %s", len(data), self._label)
            return

        proc_start = perf_us()
        _process_twist(twist, self._label)
        process_us = perf_us() - proc_start

        # Forward the original datagram bytes to all observers, no re-encode.
        for obs in list(OBSERVERS):
            obs.send_datagram(data)

        # Build & send ack in the same format the twist arrived in.
        enc_start = perf_us()
        ack = encode_ack(twist.fmt,
                         msg_id=twist.msg_id, t1=twist.t1,
                         t3=t3, t4=now_ms(),
                         decode_us=decode_us, process_us=process_us,
                         encode_us=0)
        encode_us = perf_us() - enc_start
        # Re-pack with the correct encode_us now that we measured it.
        ack = encode_ack(twist.fmt,
                         msg_id=twist.msg_id, t1=twist.t1,
                         t3=t3, t4=now_ms(),
                         decode_us=decode_us, process_us=process_us,
                         encode_us=encode_us)
        self.send_datagram(ack)

    def _handle_sync(self, data: bytes) -> None:
        t2 = now_ms()
        req = decode_sync_req(data)
        if req is None:
            logger.warning("sync decode failed (%dB) from %s", len(data), self._label)
            return
        t3 = now_ms()
        resp = encode_sync_resp(req.fmt, t1=req.t1, t2=t2, t3=t3)
        self.send_datagram(resp)
        logger.debug("sync %s t1=%d t2=%d t3=%d", req.fmt, req.t1, t2, t3)


def _process_twist(twist, peer_label: str) -> None:
    """Print a single twist on stderr. This is the 'robot side' of the demo —
    in a real teleop stack it'd publish onto a ROS2 topic, drive a motor, etc."""
    fields = ", ".join(f"{n}={v:+.3f}" for n, v in twist.selected_fields())
    logger.info(
        "TWIST %s id=%-6d t1=%d mask=0x%02x prec=%s [%s] (from %s)",
        twist.fmt, twist.msg_id, twist.t1, twist.mask,
        "f32" if twist.half_precision else "f64",
        fields or "—",
        peer_label,
    )


# ── QUIC / H3 plumbing ────────────────────────────────────────────────────────


class WebTransportProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None
        self._session: Optional[WTSession] = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic, enable_webtransport=True)
        elif isinstance(event, StreamReset) and self._session is not None:
            # WT streams aren't used by the dashboard; nothing to clean.
            pass

        if self._http is not None:
            for h3_event in self._http.handle_event(event):
                self._h3_event_received(h3_event)

    def connection_lost(self, exc) -> None:  # type: ignore[override]
        if self._session is not None:
            BROWSERS.discard(self._session)
            OBSERVERS.discard(self._session)
            logger.info("peer %s (%s) disconnected — browsers=%d observers=%d",
                        self._session.label, self._session.role,
                        len(BROWSERS), len(OBSERVERS))
        super().connection_lost(exc)

    def _h3_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            headers = {h: v for h, v in event.headers}
            if (
                headers.get(b":method") == b"CONNECT"
                and headers.get(b":protocol") == b"webtransport"
            ):
                self._handshake_webtransport(event.stream_id, headers)
            else:
                self._send_response(event.stream_id, 400, end_stream=True)
            return

        if self._session is not None:
            self._session.h3_event_received(event)

    def _handshake_webtransport(self, stream_id: int, headers: Dict[bytes, bytes]) -> None:
        path_raw = headers.get(b":path")
        if headers.get(b":authority") is None or path_raw is None:
            self._send_response(stream_id, 400, end_stream=True)
            return

        path_str = path_raw.decode("ascii", errors="replace")
        parts = urlsplit(path_str)
        if parts.path != "/wt":
            self._send_response(stream_id, 404, end_stream=True)
            return

        qs = parse_qs(parts.query)
        role = (qs.get("role") or ["observer"])[0]
        if role not in ("browser", "observer"):
            role = "observer"

        peer_addr = self._quic._network_paths[0].addr if self._quic._network_paths else ("?", 0)
        peer_label = f"{peer_addr[0]}:{peer_addr[1]}#{stream_id}"
        self._session = WTSession(stream_id, self._http, self, role, peer_label)

        if role == "browser":
            BROWSERS.add(self._session)
        else:
            OBSERVERS.add(self._session)
        logger.info("peer %s connected as %s — browsers=%d observers=%d",
                    peer_label, role, len(BROWSERS), len(OBSERVERS))

        self._send_response(stream_id, 200)

    def _send_response(self, stream_id: int, status_code: int, end_stream: bool = False) -> None:
        headers = [(b":status", str(status_code).encode())]
        if status_code == 200:
            headers.append((b"sec-webtransport-http3-draft", b"draft02"))
        self._http.send_headers(stream_id=stream_id, headers=headers, end_stream=end_stream)


# ── Entry point ───────────────────────────────────────────────────────────────


async def main(cert: str, key: str, host: str, port: int) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_datagram_frame_size=65536,
    )
    configuration.load_cert_chain(cert, key)

    await serve(
        host, port,
        configuration=configuration,
        create_protocol=WebTransportProtocol,
    )
    logger.info("listening on https://%s:%d/wt   (?role=browser | ?role=observer)",
                host, port)
    await asyncio.Future()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--cert", default="../webtransport/cert_ec.pem")
    p.add_argument("--key",  default="../webtransport/key_ec.pem")
    p.add_argument("--host", default=BIND_ADDRESS)
    p.add_argument("--port", type=int, default=BIND_PORT)
    args = p.parse_args()

    try:
        asyncio.run(main(args.cert, args.key, args.host, args.port))
    except KeyboardInterrupt:
        pass
