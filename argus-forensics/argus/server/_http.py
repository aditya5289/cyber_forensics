"""Shared HTTP server behaviour for the local ARGUS servers."""

from __future__ import annotations

import sys
from http.server import ThreadingHTTPServer

_CLIENT_GONE = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)


class TolerantThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that doesn't dump a traceback for a client that
    simply went away.

    A browser tab closing or refreshing mid-poll aborts the connection while
    socketserver is still reading the request line — before the handler runs,
    so the handlers' own guards around these errors never apply. Left alone,
    the default handle_error prints a full traceback to stderr for every one,
    which on a UI that long-polls for job logs happens constantly and is not
    a server fault.
    """

    def handle_error(self, request, client_address) -> None:
        exc_type = sys.exc_info()[0]
        if exc_type is not None and issubclass(exc_type, _CLIENT_GONE):
            return
        super().handle_error(request, client_address)
