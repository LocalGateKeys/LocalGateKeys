#!/usr/bin/env python3
"""Preview website/public/ locally the way Cloudflare Pages serves it.

The site links to extensionless URLs (/features, /de/), as Pages serves them. A plain static server
does not map /features to features.html, so this one does: a path without a file falls back to
path + ".html", and a missing page gets 404.html. Standard library only; listens on 127.0.0.1.

    python website/serve.py            # http://127.0.0.1:8765/
    python website/serve.py 9000
"""

from __future__ import annotations

import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

PUBLIC = Path(__file__).resolve().parent / "public"


class PagesHandler(SimpleHTTPRequestHandler):
    def send_head(self):
        parts = urlsplit(self.path)
        rel = unquote(parts.path).lstrip("/")
        target = (PUBLIC / rel).resolve()
        if PUBLIC in target.parents or target == PUBLIC:
            if not target.exists() and target.with_name(target.name + ".html").is_file():
                self.path = "/" + rel + ".html" + (f"?{parts.query}" if parts.query else "")
            elif not target.exists():
                self.send_response(404)
                body = (PUBLIC / "404.html").read_bytes()
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                from io import BytesIO
                return BytesIO(body)
        return super().send_head()


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    server = ThreadingHTTPServer(("127.0.0.1", port), partial(PagesHandler, directory=str(PUBLIC)))
    print(f"Serving {PUBLIC} at http://127.0.0.1:{port}/ (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        # Ctrl+C is the normal way to stop this server; exit quietly.
        pass


if __name__ == "__main__":
    main()
