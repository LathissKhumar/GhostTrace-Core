"""GhostTrace evidence parsers — convert raw security logs to evidence JSON."""

from parsers.base import BaseParser
from parsers.csv_parser import CSVParser
from parsers.zeek_parser import ZeekParser
from parsers.sysmon_parser import SysmonParser
from parsers.text_parser import TextParser
from parsers.validator import validate_evidence, list_supported_formats

__all__ = [
    "BaseParser",
    "CSVParser",
    "ZeekParser",
    "SysmonParser",
    "TextParser",
    "auto_detect_and_parse",
    "validate_evidence",
    "list_supported_formats",
]

_PARSERS = [CSVParser(), ZeekParser(), SysmonParser(), TextParser()]


def auto_detect_and_parse(content: bytes, filename: str) -> dict:
    """Auto-detect file format and parse into GhostTrace evidence format.

    Tries each parser in order. Returns the first successful parse.
    Raises ValueError if no parser can handle the file.

    Args:
        content: Raw file bytes.
        filename: Original filename (used for format detection and metadata).

    Returns:
        A dict matching the GhostTrace evidence schema.

    Raises:
        ValueError: If no parser can handle the file.
    """
    for parser in _PARSERS:
        if parser.can_parse(content, filename):
            return parser.parse(content, filename)
    raise ValueError(
        f"Unable to parse file '{filename}'. "
        f"Supported formats: CSV, Zeek conn.log, Sysmon JSON, syslog text."
    )
