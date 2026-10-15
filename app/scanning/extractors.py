"""Safe file inspection and text extraction utilities."""

import os
from typing import BinaryIO

# Magic byte signatures of executable files that must be rejected immediately
EXECUTABLE_SIGNATURES = [
    b"\x7fELF",  # Linux ELF
    b"MZ",  # Windows PE EXE / DLL
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",  # Java class / Universal binary
    b"PK\x03\x04",  # ZIP archive (prevent zip-bomb/nested macro execution in simple text scanner)
]


class ExtractionError(Exception):
    """Raised when file extraction fails safety checks."""

    pass


def validate_file_safety(
    filename: str, file_stream: BinaryIO, max_size_bytes: int, allowed_extensions: set[str]
) -> int:
    """Validate filename, extension, size, and magic bytes before reading into memory."""
    # 1. Filename & extension checks
    if not filename or "." not in filename:
        raise ExtractionError("Invalid or missing file extension.")

    # Prevent path traversal
    clean_name = os.path.basename(filename)
    if clean_name != filename or ".." in filename or "/" in filename or "\\" in filename:
        raise ExtractionError("Path traversal pattern detected in filename.")

    ext = clean_name.rsplit(".", 1)[1].lower()
    if ext not in allowed_extensions:
        raise ExtractionError(
            f"File extension '.{ext}' is not authorized. Allowed extensions: {', '.join(sorted(allowed_extensions))}"
        )

    # 2. Check header magic bytes for executables
    header = file_stream.read(16)
    file_stream.seek(0, os.SEEK_END)
    file_size = file_stream.tell()
    file_stream.seek(0)

    if file_size > max_size_bytes:
        raise ExtractionError(
            f"File size ({file_size} bytes) exceeds maximum allowable limit ({max_size_bytes} bytes)."
        )

    for sig in EXECUTABLE_SIGNATURES:
        if header.startswith(sig):
            raise ExtractionError("Uploaded file contains binary or executable signatures and was blocked.")

    return file_size


def extract_safe_text(file_stream: BinaryIO, max_bytes: int) -> str:
    """Safely decode text from an authorized stream using UTF-8 / latin-1 fallback."""
    raw_data = file_stream.read(max_bytes)

    # Reject null bytes which typically indicate compiled binary files
    if b"\x00" in raw_data[:1024]:
        raise ExtractionError("File contains binary null bytes and cannot be scanned as plain text.")

    try:
        return raw_data.decode("utf-8")
    except UnicodeDecodeError:
        # Fallback to Latin-1 with replacement characters to prevent decoding failure attacks
        return raw_data.decode("latin-1", errors="replace")
