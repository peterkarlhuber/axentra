"""A fault-injection proxy between Axentra and PostgreSQL (TABRION QA-25, MIG-T-AXE-8).

The proxy forwards the PostgreSQL wire protocol unchanged until it is armed. Armed with a ``marker`` (bytes of a
statement, for example ``b"INSERT INTO axentra_users"``), it drops the connection that sent the marker as soon as the
server starts to answer it: the server has received and executed the statement, the client gets no answer (a lost
connection after the statement was sent). With ``then`` (for example ``b"COMMIT"``) it waits for that next message
instead, so the server has committed when the client loses the connection. It cuts once, then forwards again, so a
retry by the client would reach the server and show up in the server-side count of the test.

This is the "drop after send" mode of Tabrion's ``tabrion.testing.faults`` (QA-3), built from the standard library
so that Axentra's tests need no Tabrion dependency before TABRION MIG-AXE-1. Connections through it must not use
TLS or GSS encryption (:meth:`CutProxy.url` sets ``sslmode=disable`` and ``gssencmode=disable``).
"""

from __future__ import annotations

from contextlib import suppress
import socket
import threading

from psycopg.conninfo import conninfo_to_dict, make_conninfo


class CutProxy:
    """A TCP proxy to ``host:port`` on a free local port; see the module docstring."""

    def __init__(self, host: str, port: int) -> None:
        self.target = (host, port)
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._lock = threading.Lock()
        self._marker: bytes | None = None
        self._then: bytes | None = None
        #: How often the proxy cut a connection.
        self.cuts = 0
        self._closed = False
        threading.Thread(target=self._accept, name="cut-proxy", daemon=True).start()

    @classmethod
    def for_url(cls, url: str) -> CutProxy:
        params = conninfo_to_dict(url)
        return cls(str(params.get("host") or "127.0.0.1"), int(params.get("port") or 5432))

    def url(self, url: str) -> str:
        """``url`` through this proxy."""
        params = conninfo_to_dict(url)
        params.update(host="127.0.0.1", port=str(self.port), sslmode="disable", gssencmode="disable")
        return make_conninfo(**params)

    def arm(self, marker: bytes, then: bytes | None = None) -> None:
        """Cut the next connection that sends ``marker`` (and then ``then``) when the server answers."""
        with self._lock:
            self._marker, self._then = marker, then

    def close(self) -> None:
        self._closed = True
        with suppress(OSError):
            self._listener.close()

    def _accept(self) -> None:
        while not self._closed:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            try:
                server = socket.create_connection(self.target, timeout=10)
            except OSError:
                client.close()
                continue
            server.settimeout(None)
            _Pair(self, client, server).start()

    def _claim(self) -> tuple[bytes, bytes | None] | None:
        """The armed marker, taken by the first connection that sends it (cut once)."""
        with self._lock:
            if self._marker is None:
                return None
            return self._marker, self._then

    def _fired(self) -> None:
        with self._lock:
            self._marker = self._then = None
            self.cuts += 1


class _Pair:
    """One proxied connection: a pump per direction."""

    def __init__(self, proxy: CutProxy, client: socket.socket, server: socket.socket) -> None:
        self.proxy, self.client, self.server = proxy, client, server
        #: "" -> "seen" (marker sent) -> "cut" (the next server bytes drop the connection).
        self.state = ""
        self._tail = b""

    def start(self) -> None:
        threading.Thread(target=self._upstream, daemon=True).start()
        threading.Thread(target=self._downstream, daemon=True).start()

    def _close(self) -> None:
        for sock in (self.client, self.server):
            with suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            with suppress(OSError):
                sock.close()

    def _upstream(self) -> None:
        try:
            while data := self.client.recv(65536):
                armed = self.proxy._claim()
                if armed is not None and self.state != "cut":
                    marker, then = armed
                    window = self._tail + data
                    if self.state == "" and marker in window:
                        self.state = "seen" if then is not None else "cut"
                        window = window[window.index(marker) + len(marker) :]
                    if self.state == "seen" and then is not None and then in window:
                        self.state = "cut"
                    self._tail = window[-64:]
                self.server.sendall(data)
        except OSError:
            pass
        finally:
            self._close()

    def _downstream(self) -> None:
        try:
            while data := self.server.recv(65536):
                if self.state == "cut":
                    self.proxy._fired()
                    self.state = "done"
                    return  # the answer is never forwarded
                self.client.sendall(data)
        except OSError:
            pass
        finally:
            self._close()
