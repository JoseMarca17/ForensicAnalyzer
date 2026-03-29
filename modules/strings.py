import re

PATTERNS = {
    "flag":    r'[A-Z0-9_]{2,10}\{[^\}]{3,50}\}',
    "url":     r'https?://[^\s\x00-\x1f]{8,}',
    "ip":      r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "email":   r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "base64":  r'[A-Za-z0-9+/]{20,}={0,2}',
    "hash_md5": r'\b[0-9a-fA-F]{32}\b',
    "path":    r'(?:/[\w.-]+){2,}',
    "windows_path": r'[A-Za-z]:\\[\w\\.-]+',
}

def extract_strings(filepath: str, min_length: int = 4) -> list[str]:
    strings = []
    
    with open(filepath, "rb") as f:
        data = f.read()
        
    pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    matches = re.findall(pattern, data)
    strings = [m.decode("ascii") for m in matches]
    
    return strings

def find_patterns(filepath: str) -> dict[str, list[str]]:
    strings = extract_strings(filepath, min_length=4)
    full_text = "\n".join(strings)
    
    results = {}
    for name, pattern, in PATTERNS.items():
        matches = re.findall(pattern, full_text)
        if matches:
            results[name] = list(set(matches))
    
    return results

def struct_strings_unicode(filepath: str, min_length: int=4) -> list[str]:
    strings = []

    with open(filepath, "rb") as f:
        data = f.read()

    pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
    matches = re.findall(pattern, data)
    for m in matches:
        try:
            strings.append(m.decode("utf-16-le"))
        except Exception:
            continue

    return strings