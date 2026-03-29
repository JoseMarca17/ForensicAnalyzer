import os

MAGIC_SIGNATURES = [
    (b'\x89PNG\r\n\x1a\n', 0, "PNG image"),
    (b'\xff\xd8\xff',       0, "JPEG image"),
    (b'GIF87a',             0, "GIF image (87a)"),
    (b'GIF89a',             0, "GIF image (89a)"),
    (b'%PDF',               0, "PDF document"),
    (b'PK\x03\x04',         0, "ZIP archive"),
    (b'PK\x05\x06',         0, "ZIP archive (empty)"),
    (b'\x1f\x8b',           0, "GZIP archive"),
    (b'BZh',                0, "BZIP2 archive"),
    (b'\x7fELF',            0, "ELF executable"),
    (b'MZ',                 0, "Windows executable (PE)"),
    (b'\xff\xfe',           0, "UTF-16 LE text"),
    (b'\xfe\xff',           0, "UTF-16 BE text"),
    (b'RIFF',               0, "RIFF container (WAV/AVI)"),
    (b'\x00\x00\x00\x18ftyp', 0, "MP4 video"),
    (b'OggS',               0, "OGG media"),
    (b'ID3',                0, "MP3 audio"),
    (b'RAR!',               0, "RAR archive"),
    (b'7z\xbc\xaf\x27\x1c', 0, "7-Zip archive"),
    (b'\xd0\xcf\x11\xe0',   0, "Microsoft Office (legacy)"),
    (b'SQLite format 3',    0, "SQLite database"),
]

def identify_file(filepath: str) -> dict:
    if not os.path.exists(filepath):
        return {
            "error": f"FIle not found: {filepath}"
        }
    
    result = {
        "path": filepath,
        "size": os.path.getsize(filepath),
        "extension": os.path.splitext(filepath)[1].lower(),
        "real_type": None,
        "mismatch": False
    }
    
    with open(filepath, "rb") as f:
        header = f.read(32)
    
    result["real_type"] = _match_magic(header)
    result["hex_header"] = header.hex(" ")[:47]
    
    if result["real_type"]:
        result["mismatch"] = not _extension_matches(
            result["extension"],
            result["real_type"]
        )
    return result

def _match_magic(header: bytes) -> str | None:
    for magic, offset, name in MAGIC_SIGNATURES:
        if header[offset:offset + len(magic)] == magic:
            return name
    return None

def _extension_matches(extension: str, real_type: str) -> bool:
    extension_map = {
        ".png": "PNG",
        ".jpg": "JPEG",
        ".jpeg": "JPEG",
        ".gif": "GIF",
        ".pdf": "PDF",
        ".zip": "ZIP",
        ".gz":  "GZIP",
        ".bz2": "BZIP2",
        ".elf": "ELF",
        ".exe": "Windows executable",
        ".mp4": "MP4",
        ".mp3": "MP3",
        ".rar": "RAR",
        ".7z":  "7-Zip",
        ".db":  "SQLite",
    }
    expected = extension_map.get(extension, "")
    return expected.lower() in real_type.lower()