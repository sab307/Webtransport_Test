#!/usr/bin/env python3
"""
WebTransport observer client.

Connects to the teleop server as `role=observer`, decodes every Twist datagram
the server forwards (binary CRC-8 or JSON envelope, auto-detected per-message),
prints it to the terminal, and republishes it onto a ROS 2 topic
(default ``/cmd_vel``).

Terminal output example::

  Publishing twists to ROS 2 topic: /cmd_vel
  [HH:MM:SS.mmm] /cmd_vel  twist json   id=42   mask=0x22 linear_y=+0.500 angular_z=-0.300
  [HH:MM:SS.mmm] /cmd_vel  twist binary id=7234 mask=0x22 linear_y=-0.250 angular_z=+0.100

If ``rclpy`` is importable, a publisher is created on the chosen topic and each
twist is published as ``geometry_msgs/Twist``. If ``rclpy`` is unavailable, the
script keeps running and just prints — the topic is still shown so you know
where the data would have gone.

Usage:
  python3 client.py                                       # role=observer, /cmd_vel
  python3 client.py --topic /robot1/cmd_vel
  python3 client.py --url https://localhost:4433/wt --insecure
  python3 client.py --role browser                        # connect as browser
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import ssl
import sys
import time
from typing import Optional
from urllib.parse import urlencode, urlparse, urlsplit

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    H3Event,
    HeadersReceived,
    WebTransportStreamDataReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent

from twist_protocol import (
    MSG_TWIST, Twist,
    decode_twist, peek_type,
)

logger = logging.getLogger("wt-observer")


# ── Optional ROS 2 publisher ──────────────────────────────────────────────────
# rclpy is imported lazily so the script still runs (decode + print) when ROS 2
# isn't sourced. With ROS 2 sourced (e.g. `source /opt/ros/humble/setup.bash`),
# each received twist is published as geometry_msgs/Twist on --topic.

class TwistPublisher:
    """Publishes Twist messages on a ROS 2 topic, or no-ops if rclpy is absent."""

    def __init__(self, topic: str):
        self.topic = topic
        self._node = None
        self._pub = None
        self._twist_cls = None
        try:
            import rclpy                              # type: ignore
            from rclpy.node import Node               # type: ignore
            from geometry_msgs.msg import Twist as TwistMsg  # type: ignore
        except Exception as e:
            print(f"rclpy not available ({e.__class__.__name__}) — "
                  f"twists will be printed only, not published to {topic}",
                  flush=True)
            return

        rclpy.init(args=None)
        self._rclpy = rclpy
        self._node = rclpy.create_node("wt_twist_observer")
        self._pub = self._node.create_publisher(TwistMsg, topic, 10)
        self._twist_cls = TwistMsg
        print(f"Publishing twists to ROS 2 topic: {topic}", flush=True)

    @property
    def active(self) -> bool:
        return self._pub is not None

    def publish(self, twist: Twist) -> None:
        if self._pub is None or self._twist_cls is None:
            return
        msg = self._twist_cls()
        msg.linear.x  = float(twist.linear_x)
        msg.linear.y  = float(twist.linear_y)
        msg.linear.z  = float(twist.linear_z)
        msg.angular.x = float(twist.angular_x)
        msg.angular.y = float(twist.angular_y)
        msg.angular.z = float(twist.angular_z)
        self._pub.publish(msg)

    def shutdown(self) -> None:
        if self._node is not None:
            try: self._node.destroy_node()
            except Exception: pass
        if self._pub is not None:
            try: self._rclpy.shutdown()
            except Exception: pass


# Module-level instance so the H3 datagram callback can reach it without
# threading the publisher through aioquic's protocol class.
_PUBLISHER: Optional[TwistPublisher] = None


class WebTransportClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, authority: str, path: str, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._authority = authority
        self._path = path
        self._http: Optional[H3Connection] = None
        self._session_id: Optional[int] = None
        self._ready = asyncio.Event()

    async def wait_ready(self) -> None:
        await self._ready.wait()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic, enable_webtransport=True)
            self._open_connect_request()
        if self._http is not None:
            for h3_event in self._http.handle_event(event):
                self._h3_event_received(h3_event)

    def _open_connect_request(self) -> None:
        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self._session_id = stream_id
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method",     b"CONNECT"),
                (b":protocol",   b"webtransport"),
                (b":scheme",     b"https"),
                (b":authority",  self._authority.encode("ascii")),
                (b":path",       self._path.encode("ascii")),
                (b"sec-webtransport-http3-draft02", b"1"),
            ],
            end_stream=False,
        )
        self.transmit()
        logger.info("CONNECT %s%s (stream %d)",
                    self._authority, self._path, stream_id)

    def _h3_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            status = next((v for h, v in event.headers if h == b":status"), b"")
            if status == b"200":
                logger.info("session ready")
                self._ready.set()
            else:
                logger.error("CONNECT rejected status=%s", status.decode())

        elif isinstance(event, DatagramReceived):
            _on_datagram(bytes(event.data))

        elif isinstance(event, WebTransportStreamDataReceived):
            # Observer doesn't expect stream traffic, but tolerate it.
            pass


def _on_datagram(data: bytes) -> None:
    ts = time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"
    topic = _PUBLISHER.topic if _PUBLISHER is not None else "(no topic)"
    mtype = peek_type(data)
    if mtype != MSG_TWIST:
        print(f"[{ts}] (non-twist, type={mtype}, {len(data)}B)", flush=True)
        return

    twist = decode_twist(data)
    if twist is None:
        print(f"[{ts}] BAD twist frame ({len(data)}B)", flush=True)
        return

    if _PUBLISHER is not None:
        try:
            _PUBLISHER.publish(twist)
        except Exception as e:
            print(f"[{ts}] publish failed: {e}", flush=True)

    fields = " ".join(f"{n}={v:+.3f}" for n, v in twist.selected_fields()) or "(none)"
    print(
        f"[{ts}] {topic}  twist {twist.fmt:6s} "
        f"id={twist.msg_id:<6} mask=0x{twist.mask:02x} "
        f"{'f32' if twist.half_precision else 'f64'} {fields}",
        flush=True,
    )


def _build_path(url_path: str, role: str) -> str:
    """Append ?role=… to the URL path if not already present."""
    parts = urlsplit(url_path)
    qs = parts.query
    if "role=" in qs:
        return url_path
    sep = "&" if qs else "?"
    return f"{url_path}{sep}{urlencode({'role': role})}"


async def main(url: str, role: str, topic: str,
               ca: Optional[str], insecure: bool) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    global _PUBLISHER
    _PUBLISHER = TwistPublisher(topic)

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise SystemExit("URL must be https://")
    host = parsed.hostname or "localhost"
    port = parsed.port or 443
    authority = f"{host}:{port}"

    path_with_query = parsed.path or "/wt"
    if parsed.query:
        path_with_query += "?" + parsed.query
    path = _build_path(path_with_query, role)

    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        max_datagram_frame_size=65536,
    )
    if ca:
        configuration.load_verify_locations(ca)
    if insecure:
        configuration.verify_mode = ssl.CERT_NONE

    async with connect(
        host, port,
        configuration=configuration,
        create_protocol=lambda *a, **kw:
            WebTransportClientProtocol(*a, authority=authority, path=path, **kw),
    ) as protocol:
        assert isinstance(protocol, WebTransportClientProtocol)
        await protocol.wait_ready()
        print(f"observing twist stream from {url} (role={role})  — Ctrl-C to quit",
              flush=True)
        try:
            await asyncio.Future()  # run until interrupted
        except asyncio.CancelledError:
            pass
        finally:
            if _PUBLISHER is not None:
                _PUBLISHER.shutdown()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url",   default="https://localhost:4433/wt")
    p.add_argument("--role",  default="observer", choices=("observer", "browser"))
    p.add_argument("--topic", default="/cmd_vel",
                   help="ROS 2 topic to publish received twists on "
                        "(default: /cmd_vel)")
    p.add_argument("--ca",    default="../webtransport/cert_ec.pem")
    p.add_argument("--insecure", action="store_true")
    args = p.parse_args()

    try:
        asyncio.run(main(args.url, args.role, args.topic,
                         args.ca, args.insecure))
    except KeyboardInterrupt:
        pass
