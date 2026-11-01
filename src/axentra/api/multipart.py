"""Streaming ``multipart/form-data`` parsing for file uploads with limits enforced while reading.

Starlette's form parser spools a whole file part before the handler runs and has no per-file size
limit. This parser reads the request body chunk by chunk and stops as soon as the file part
exceeds ``max_file_bytes`` or the other fields exceed their budget; ``Content-Length`` is used only
to refuse obviously oversized requests early, never trusted as the real size. The file part is
spooled to a temporary file (memory up to 1 MiB, then disk) and handed to the storage service.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from tempfile import SpooledTemporaryFile
from typing import Any

from python_multipart.multipart import MultipartParser, parse_options_header
from starlette.requests import ClientDisconnect, Request

from axentra.core.errors import PayloadTooLarge, UnsupportedMediaType, ValidationFailed

SPOOL_MAX = 1024 * 1024
FIELD_BUDGET = 64 * 1024
MAX_PARTS = 8


@dataclass
class UploadForm:
    file: SpooledTemporaryFile[bytes] | None = None
    filename: str = ""
    content_type: str | None = None
    size: int = 0
    fields: dict[str, str] = field(default_factory=dict)

    def close(self) -> None:
        if self.file is not None:
            self.file.close()


class _State:
    def __init__(self, form: UploadForm, max_file_bytes: int) -> None:
        self.form = form
        self.max_file_bytes = max_file_bytes
        self.error: Exception | None = None
        self.parts = 0
        self.field_bytes = 0
        self.header_field = b""
        self.header_value = b""
        self.headers: dict[bytes, bytes] = {}
        self.current: str | None = None  # "file", a field name, or None (ignored part)
        self.buf = bytearray()

    def fail(self, exc: Exception) -> None:
        if self.error is None:
            self.error = exc

    # callbacks ---------------------------------------------------------------------------------

    def on_part_begin(self) -> None:
        self.parts += 1
        self.headers = {}
        self.current = None
        self.buf = bytearray()
        if self.parts > MAX_PARTS:
            self.fail(ValidationFailed("too many form parts"))

    def on_header_field(self, data: bytes, start: int, end: int) -> None:
        self.header_field += data[start:end]

    def on_header_value(self, data: bytes, start: int, end: int) -> None:
        self.header_value += data[start:end]

    def on_header_end(self) -> None:
        self.headers[self.header_field.lower()] = self.header_value
        self.header_field = b""
        self.header_value = b""

    def on_headers_finished(self) -> None:
        _, opts = parse_options_header(self.headers.get(b"content-disposition", b""))
        name = opts.get(b"name", b"").decode("utf-8", "replace")
        if name == "file":
            if self.form.file is not None:
                self.fail(ValidationFailed("only one file per upload"))
                return
            filename = opts.get(b"filename*") or opts.get(b"filename") or b""
            self.form.filename = filename.decode("utf-8", "replace")
            ctype = self.headers.get(b"content-type")
            self.form.content_type = ctype.decode("latin-1") if ctype else None
            self.form.file = SpooledTemporaryFile(max_size=SPOOL_MAX)  # noqa: SIM115 - closed by UploadForm.close
            self.current = "file"
        elif name in ("metadata", "expires_at", "name"):
            self.current = name
        else:
            self.current = None

    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        if self.error is not None:
            return
        n = end - start
        if self.current == "file":
            assert self.form.file is not None
            self.form.size += n
            if self.form.size > self.max_file_bytes:
                self.fail(PayloadTooLarge(f"files may be at most {self.max_file_bytes} bytes"))
                return
            self.form.file.write(data[start:end])
            return
        self.field_bytes += n
        if self.field_bytes > FIELD_BUDGET:
            self.fail(PayloadTooLarge("form fields are too large"))
            return
        if self.current is not None:
            self.buf += data[start:end]

    def on_part_end(self) -> None:
        if self.current not in (None, "file") and self.error is None:
            try:
                self.form.fields[self.current] = self.buf.decode("utf-8")
            except UnicodeDecodeError:
                self.fail(ValidationFailed(f"{self.current} must be UTF-8"))
        self.current = None


async def parse_upload(request: Request, *, max_file_bytes: int) -> UploadForm:
    ctype, params = parse_options_header(request.headers.get("content-type", ""))
    if ctype != b"multipart/form-data" or not params.get(b"boundary"):
        raise UnsupportedMediaType("uploads must be multipart/form-data with a 'file' part")
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > max_file_bytes + FIELD_BUDGET + 16 * 1024:
        raise PayloadTooLarge(f"files may be at most {max_file_bytes} bytes")
    form = UploadForm()
    state = _State(form, max_file_bytes)
    callbacks: Any = {
        "on_part_begin": state.on_part_begin,
        "on_header_field": state.on_header_field,
        "on_header_value": state.on_header_value,
        "on_header_end": state.on_header_end,
        "on_headers_finished": state.on_headers_finished,
        "on_part_data": state.on_part_data,
        "on_part_end": state.on_part_end,
    }
    parser = MultipartParser(params[b"boundary"], callbacks)
    try:
        try:
            async for chunk in request.stream():
                if chunk:
                    parser.write(chunk)
                if state.error is not None:
                    raise state.error
            parser.finalize()
        except ClientDisconnect:
            raise ValidationFailed("the upload was interrupted") from None
        except (PayloadTooLarge, ValidationFailed, UnsupportedMediaType):
            raise
        except Exception:
            raise ValidationFailed("malformed multipart body") from None
        if state.error is not None:
            raise state.error
        if form.file is None:
            raise ValidationFailed("the upload needs a 'file' part")
        form.file.seek(0)
        return form
    except BaseException:
        form.close()
        raise
