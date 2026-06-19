# serves the resources saved by save-script.py out of <destdir>/[host]/[path]
#
# usage: mitmdump -s serve-script.py
#
# Any request whose corresponding file exists on disk is answered locally;
# anything else is 404'd
import os
import mimetypes
import hashlib
from typing import Optional

from mitmproxy import ctx, exceptions, http
from urllib.parse import urlparse

# mitmproxy renamed http.HTTPResponse -> http.Response in v7. Support both so
# this works on the installed 6.0.2 as well as newer versions.
Response = getattr(http, "Response", None) or http.HTTPResponse


def load(loader):
    loader.add_option(
        name="destdir",
        typespec=Optional[str],
        default=None,
        help="Directory to serve saved resources from (required)",
    )


def configure(updated):
    if "destdir" in updated and not ctx.options.destdir:
        raise exceptions.OptionsError("destdir is required (set it with --set destdir=...)")


def sniff_content_type(content):
    """Guess a content type from the bytes when the extension tells us nothing.

    Covers the cases that actually show up when serving a saved web page;
    returns None if we can't make a confident guess.
    """
    if not content:
        return None

    # binary formats with stable magic numbers
    signatures = [
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"BM", "image/bmp"),
        (b"%PDF-", "application/pdf"),
        (b"wOFF", "font/woff"),
        (b"wOF2", "font/woff2"),
        (b"\x00\x01\x00\x00", "font/ttf"),
        (b"OTTO", "font/otf"),
        (b"\x1f\x8b", "application/gzip"),
    ]
    for sig, ctype in signatures:
        if content.startswith(sig):
            return ctype
    # RIFF-based containers carry the real type at offset 8
    if content.startswith(b"RIFF") and content[8:12] == b"WEBP":
        return "image/webp"

    # text-based formats: sniff from the first non-whitespace bytes
    head = content[:512].lstrip()
    lowered = head.lower()
    if lowered.startswith((b"<!doctype html", b"<html")):
        return "text/html"
    if lowered.startswith(b"<?xml") or lowered.startswith(b"<svg"):
        return "image/svg+xml" if b"<svg" in lowered else "text/xml"
    if head.startswith((b"{", b"[")):
        return "application/json"
    # is it plausibly text at all? (no NUL bytes in the sample)
    try:
        content[:512].decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"


def saved_path(url):
    """Mirror the path layout produced by save-script.py."""
    parsed = urlparse(url)
    file_path = parsed.path
    # a directory / trailing-slash URL was saved as index.html
    if os.path.basename(file_path) == "":
        file_path = os.path.join(file_path, "index.html")
    # query string is part of the saved filename so distinct queries map to
    # distinct files (kept in sync with save-script.py)
    if parsed.query:
        query = parsed.query
        # keep the filename component within the 255-byte limit most
        # filesystems impose; hash overly long queries instead
        if len((os.path.basename(file_path) + "?" + query).encode("utf-8")) > 255:
            query = hashlib.sha256(query.encode("utf-8")).hexdigest()
        file_path = file_path + "?" + query
    return os.path.join(ctx.options.destdir, parsed.hostname or "", file_path.lstrip("/"))


def cors_headers(flow):
    """Permissive CORS headers.

    We reflect the request Origin rather than sending "*" so that requests made
    with credentials (cookies) still pass the browser's CORS check; "*" is
    rejected in that case. Falls back to "*" when no Origin is present.
    """
    origin = flow.request.headers.get("Origin", "*")
    headers = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": flow.request.headers.get(
            "Access-Control-Request-Headers", "*"
        ),
        "Access-Control-Expose-Headers": "*",
        "Access-Control-Max-Age": "86400",
    }
    if origin != "*":
        # Allow-Credentials is only meaningful with a non-wildcard origin.
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Vary"] = "Origin"
    return headers


def request(flow):
    # Answer CORS preflights ourselves — there is no saved file for them.
    if flow.request.method == "OPTIONS":
        ctx.log.info(f"Answering CORS preflight for {flow.request.url}")
        flow.response = Response.make(204, b"", cors_headers(flow))
        return

    path = saved_path(flow.request.url)
    if not os.path.isfile(path):
        ctx.log.info(f"No saved file for {flow.request.url} (looked for {path})")
        flow.response = Response.make(
            404, b"Not saved\n", cors_headers(flow)
        )
        return

    with open(path, "rb") as f:
        content = f.read()

    # guess the type from the URL path without the query — the query is part
    # of the saved filename, but ".../script.js?v=2" must still match ".js"
    content_type, _ = mimetypes.guess_type(urlparse(flow.request.url).path)
    if not content_type:
        content_type = sniff_content_type(content)
    headers = cors_headers(flow)
    if content_type:
        headers["Content-Type"] = content_type

    ctx.log.info(f"Serving {flow.request.url} from {path}")
    # save-script.py stored decoded bodies, so we serve them as-is with no
    # content-encoding; mitmproxy will set Content-Length for us.
    flow.response = Response.make(200, content, headers)