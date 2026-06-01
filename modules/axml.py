"""
APKOwl :: modules.axml
=====================

A self-contained parser for Android's binary XML (AXML) format.

Android compiles ``AndroidManifest.xml`` and the files under ``res/`` into a
packed binary representation. When ``apktool`` is available we use its decoded
output, but we never want to be *dependent* on it — so this module reimplements
enough of the AXML chunk format to recover the manifest as plain XML text.

The format is a sequence of chunks:
  * RES_STRING_POOL_TYPE  (0x0001) — the string pool
  * RES_XML_RESOURCE_MAP  (0x0180) — attribute name -> resource id map
  * RES_XML_START_NAMESPACE(0x0100)
  * RES_XML_END_NAMESPACE  (0x0101)
  * RES_XML_START_ELEMENT  (0x0102)
  * RES_XML_END_ELEMENT    (0x0103)
  * RES_XML_CDATA          (0x0104)

This implementation is deliberately defensive: malformed offsets never crash
the caller, they just yield best-effort output.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple


# chunk types
RES_NULL = 0x0000
RES_STRING_POOL = 0x0001
RES_TABLE = 0x0002
RES_XML = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP = 0x0180

# attribute value types (from ResValue)
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1C
TYPE_INT_COLOR_RGB8 = 0x1D
TYPE_INT_COLOR_ARGB4 = 0x1E
TYPE_INT_COLOR_RGB4 = 0x1F


# A subset of the public android: attribute resource-id -> name map. The binary
# manifest stores framework attribute names *by resource id only* when the
# string pool entry is empty, so we need this to recover names like
# android:name, android:exported, etc.
ANDROID_ATTR_NAMES: Dict[int, str] = {
    0x01010003: "name",
    0x01010002: "label",
    0x01010001: "theme",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x0101020C: "minSdkVersion",
    0x01010270: "targetSdkVersion",
    0x0101020E: "maxSdkVersion",
    0x01010010: "exported",
    0x0101001D: "enabled",
    0x01010006: "permission",
    0x01010273: "authorities",
    0x0101001E: "process",
    0x01010000: "theme",
    0x0101000F: "debuggable",
    0x01010280: "allowBackup",
    0x010102B2: "usesCleartextTraffic",
    0x01010204: "protectionLevel",
    0x0101026F: "installLocation",
    0x01010282: "largeHeap",
    0x0101001B: "value",
    0x01010024: "resource",
    0x010100D0: "id",
    0x01010018: "authorities",
    0x010102DC: "networkSecurityConfig",
    0x0101055C: "roundIcon",
    0x01010002: "icon",
    0x01010572: "appComponentFactory",
    0x010103E1: "fullBackupContent",
    0x01010261: "scheme",
    0x01010262: "host",
    0x01010263: "port",
    0x01010264: "path",
    0x01010265: "pathPattern",
    0x01010266: "pathPrefix",
    0x01010268: "mimeType",
    0x0101026B: "priority",
    0x01010201: "grantUriPermissions",
    0x01010003: "name",
}


class StringPool:
    """Decoder for a RES_STRING_POOL chunk."""

    def __init__(self, data: bytes, base: int) -> None:
        self.strings: List[str] = []
        self._parse(data, base)

    def _parse(self, data: bytes, base: int) -> None:
        try:
            (chunk_type, header_size, chunk_size) = struct.unpack_from("<HHI", data, base)
            (string_count, style_count, flags, strings_start, styles_start) = (
                struct.unpack_from("<IIIII", data, base + 8)
            )
        except struct.error:
            return
        is_utf8 = bool(flags & (1 << 8))
        offsets_base = base + 8 + 20
        str_data_base = base + strings_start
        for i in range(string_count):
            try:
                (offset,) = struct.unpack_from("<I", data, offsets_base + i * 4)
            except struct.error:
                self.strings.append("")
                continue
            pos = str_data_base + offset
            self.strings.append(self._read_string(data, pos, is_utf8))

    @staticmethod
    def _read_string(data: bytes, pos: int, is_utf8: bool) -> str:
        try:
            if is_utf8:
                # two length fields (chars, then bytes), each possibly 1-2 bytes
                pos, _nchars = StringPool._read_len8(data, pos)
                pos, nbytes = StringPool._read_len8(data, pos)
                raw = data[pos : pos + nbytes]
                return raw.decode("utf-8", "replace")
            else:
                pos, nchars = StringPool._read_len16(data, pos)
                raw = data[pos : pos + nchars * 2]
                return raw.decode("utf-16-le", "replace")
        except Exception:
            return ""

    @staticmethod
    def _read_len8(data: bytes, pos: int) -> Tuple[int, int]:
        val = data[pos]
        pos += 1
        if val & 0x80:
            val = ((val & 0x7F) << 8) | data[pos]
            pos += 1
        return pos, val

    @staticmethod
    def _read_len16(data: bytes, pos: int) -> Tuple[int, int]:
        (val,) = struct.unpack_from("<H", data, pos)
        pos += 2
        if val & 0x8000:
            (low,) = struct.unpack_from("<H", data, pos)
            pos += 2
            val = ((val & 0x7FFF) << 16) | low
        return pos, val

    def get(self, index: int) -> str:
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return ""


class AXMLParser:
    """Parse a binary AndroidManifest.xml into an XML string + structured tree."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pool: Optional[StringPool] = None
        self.resource_map: List[int] = []
        self.events: List[Tuple[str, dict]] = []

    # -- value formatting --------------------------------------------------
    def _format_value(self, value_type: int, data: int) -> str:
        if value_type == TYPE_STRING:
            return self.pool.get(data) if self.pool else ""
        if value_type == TYPE_INT_BOOLEAN:
            return "true" if data != 0 else "false"
        if value_type == TYPE_INT_HEX:
            return hex(data)
        if value_type == TYPE_REFERENCE:
            return f"@{hex(data)}"
        if value_type == TYPE_ATTRIBUTE:
            return f"?{hex(data)}"
        if value_type == TYPE_FLOAT:
            try:
                return str(struct.unpack("<f", struct.pack("<I", data & 0xFFFFFFFF))[0])
            except struct.error:
                return str(data)
        # signed int for decimals
        if value_type == TYPE_INT_DEC:
            if data & 0x80000000:
                return str(data - 0x100000000)
            return str(data)
        return str(data)

    def _attr_name(self, name_idx: int, ns_idx: int) -> str:
        name = self.pool.get(name_idx) if self.pool else ""
        if name:
            return name
        # name pool entry empty -> resolve via resource map
        if 0 <= name_idx < len(self.resource_map):
            res_id = self.resource_map[name_idx]
            if res_id in ANDROID_ATTR_NAMES:
                return ANDROID_ATTR_NAMES[res_id]
            return f"attr_{res_id:08x}"
        return f"attr{name_idx}"

    # -- main parse --------------------------------------------------------
    def parse(self) -> bool:
        data = self.data
        if len(data) < 8:
            return False
        try:
            magic, _hsize, _fsize = struct.unpack_from("<HHI", data, 0)
        except struct.error:
            return False
        if magic != RES_XML:
            # some manifests omit the wrapper; tolerate string pool at 0
            pass
        pos = 8
        n = len(data)
        while pos + 8 <= n:
            try:
                ctype, hsize, csize = struct.unpack_from("<HHI", data, pos)
            except struct.error:
                break
            if csize <= 0:
                break
            if ctype == RES_STRING_POOL:
                self.pool = StringPool(data, pos)
            elif ctype == RES_XML_RESOURCE_MAP:
                count = (csize - hsize) // 4
                self.resource_map = list(
                    struct.unpack_from(f"<{count}I", data, pos + hsize)
                )
            elif ctype == RES_XML_START_ELEMENT:
                self._parse_start_element(pos, hsize)
            elif ctype == RES_XML_END_ELEMENT:
                self._parse_end_element(pos)
            pos += csize
        return bool(self.events)

    def _parse_start_element(self, pos: int, hsize: int) -> None:
        data = self.data
        try:
            # header: type/hsize/csize (8) + lineno(4) + comment(4)
            _ns, name = struct.unpack_from("<iI", data, pos + 8 + 8)
            attr_start, attr_size, attr_count = struct.unpack_from(
                "<HHH", data, pos + 8 + 8 + 8
            )
        except struct.error:
            return
        tag = self.pool.get(name) if self.pool else f"tag{name}"
        attrs = {}
        attr_base = pos + 8 + 8 + attr_start
        for i in range(attr_count):
            off = attr_base + i * 20
            try:
                a_ns, a_name, a_rawval, a_typedval_size_res = struct.unpack_from(
                    "<iiiI", data, off
                )
                value_type = (a_typedval_size_res >> 24) & 0xFF
                (a_data,) = struct.unpack_from("<I", data, off + 16)
            except struct.error:
                continue
            aname = self._attr_name(a_name, a_ns)
            if a_rawval != -1 and self.pool:
                aval = self.pool.get(a_rawval)
            else:
                aval = self._format_value(value_type, a_data)
            attrs[aname] = aval
        self.events.append(("start", {"tag": tag, "attrs": attrs}))

    def _parse_end_element(self, pos: int) -> None:
        data = self.data
        try:
            _ns, name = struct.unpack_from("<iI", data, pos + 8 + 8)
        except struct.error:
            return
        tag = self.pool.get(name) if self.pool else f"tag{name}"
        self.events.append(("end", {"tag": tag}))

    # -- output ------------------------------------------------------------
    def to_xml(self) -> str:
        """Render the recovered events as indented XML text."""
        lines = ['<?xml version="1.0" encoding="utf-8"?>']
        depth = 0
        for kind, info in self.events:
            if kind == "start":
                indent = "  " * depth
                attrs = info["attrs"]
                if attrs:
                    attr_str = " ".join(
                        f'{k}="{self._escape(v)}"' for k, v in attrs.items()
                    )
                    lines.append(f"{indent}<{info['tag']} {attr_str}>")
                else:
                    lines.append(f"{indent}<{info['tag']}>")
                depth += 1
            elif kind == "end":
                depth = max(0, depth - 1)
                indent = "  " * depth
                lines.append(f"{indent}</{info['tag']}>")
        return "\n".join(lines)

    @staticmethod
    def _escape(value: str) -> str:
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )


def parse_axml_file(path: str) -> Optional[str]:
    """Convenience: read a binary AXML file and return XML text, or None."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    parser = AXMLParser(data)
    if parser.parse():
        return parser.to_xml()
    return None


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        xml = parse_axml_file(sys.argv[1])
        print(xml or "(failed to parse)")
    else:
        print("usage: python -m modules.axml <AndroidManifest.xml>")
