# saves out the fetched resources to <destdir>/[host]/[path][?query]
import os
import hashlib
from typing import Optional
from mitmproxy import ctx, exceptions
from urllib.parse import urlparse


def load(loader):
    loader.add_option(
        name="destdir",
        typespec=Optional[str],
        default=None,
        help="Directory to save fetched resources to (required)",
    )


def configure(updated):
    if "destdir" in updated and not ctx.options.destdir:
        raise exceptions.OptionsError("destdir is required (set it with --set destdir=...)")


def hash_if_long(component):
    """Hash a single path component if it exceeds the 255-byte filesystem limit."""
    if len(component.encode("utf-8")) > 255:
        return hashlib.sha256(component.encode("utf-8")).hexdigest()
    return component


def saved_path(url):
    """Compute where a URL's body is stored (kept in sync with serve-script.py)."""
    parsed = urlparse(url)
    file_path = parsed.path
    # a directory / trailing-slash URL is saved as index.html
    if os.path.basename(file_path) == "":
        file_path = os.path.join(file_path, "index.html")
    dir_part = os.path.dirname(file_path)
    filename = os.path.basename(file_path)
    # query string is part of the saved filename so distinct queries map to
    # distinct files
    if parsed.query:
        query = parsed.query
        # keep the 255-byte filename limit most filesystems impose; if only the
        # query pushes us over, hash just the query so the path stays readable
        if len((filename + "?" + query).encode("utf-8")) > 255:
            query = hashlib.sha256(query.encode("utf-8")).hexdigest()
        filename = filename + "?" + query
    # if the name is still too long the basename itself is to blame, so hash
    # the whole thing
    filename = hash_if_long(filename)
    # individual directory components are subject to the same limit; hash any
    # that are too long while leaving the readable ones intact
    parts = [hash_if_long(p) for p in dir_part.split("/")]
    parts.append(filename)
    file_path = "/".join(parts)
    return os.path.join(ctx.options.destdir, parsed.hostname or "", file_path.lstrip("/"))


def response(flow):
    ce = flow.response.headers.get("content-encoding")
    if ce == "null":
        content = flow.response.raw_content
    else:
        content = flow.response.content

    path = saved_path(flow.request.url)
    dir_name = os.path.dirname(path)
    print("dir_name", dir_name, flow.request.url)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    with open(path, "wb+") as f:
        f.write(content)
    ctx.log.info(f"Saved {flow.request.url} with {repr(ce)} to {path}")
