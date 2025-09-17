#!/usr/bin/env python3
"""
Basic static ransomware heuristic detector.
Usage:
    python static_detector.py /path/to/binary.exe
"""

import sys
import math
import pefile
import os
from collections import Counter

SUSPICIOUS_EXTS = {'.exe', '.dll', '.scr', '.js', '.vbs', '.ps1'}
HIGH_ENTROPY_THRESHOLD = 7.5  # heuristic: packed/obfuscated if entropy high

def file_entropy(path, block_size=4096):
    """Calculate Shannon entropy of file bytes."""
    with open(path, 'rb') as f:
        data = f.read()
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    ent = -sum((cnt/length) * math.log2(cnt/length) for cnt in counts.values())
    return ent

def suspicious_imports(pe):
    """Check for suspicious / uncommon imports often used by malware."""
    suspicious = []
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors='ignore').lower()
            # common windows dlls — but we can flag unusual API imports later
            if any(x in dll for x in ('crypt', 'advapi', 'ws2_32', 'ntdll')):
                suspicious.append(dll)
    except Exception:
        pass
    return suspicious

def analyze(path):
    result = {
        'path': path,
        'size': os.path.getsize(path),
        'ext': os.path.splitext(path)[1].lower(),
        'entropy': None,
        'suspicious_imports': [],
        'score': 0.0,
        'notes': []
    }

    result['entropy'] = round(file_entropy(path), 4)
    if result['entropy'] >= HIGH_ENTROPY_THRESHOLD:
        result['notes'].append('High entropy (possible packer/obfuscation)')
        result['score'] += 0.5

    if result['ext'] in SUSPICIOUS_EXTS:
        result['score'] += 0.1

    # Try PE analysis
    try:
        pe = pefile.PE(path)
        imports = suspicious_imports(pe)
        if imports:
            result['suspicious_imports'] = imports
            result['notes'].append('Suspicious imports detected: ' + ','.join(imports))
            result['score'] += 0.4
    except pefile.PEFormatError:
        result['notes'].append('Not a PE file (script/other) - consider analysing strings/obfuscation')
        # For non-PE, maybe check for script patterns later

    # Simple threshold
    result['detection'] = 'suspicious' if result['score'] >= 0.7 else ('suspicious-ish' if result['score'] >= 0.3 else 'clean-ish')
    return result

def pretty_print(res):
    print(f"Path: {res['path']}")
    print(f"Size: {res['size']} bytes, Ext: {res['ext']}")
    print(f"Entropy: {res['entropy']}")
    print("Suspicious imports:", res['suspicious_imports'])
    print("Score:", res['score'])
    print("Notes:")
    for n in res['notes']:
        print(" -", n)
    print("Final:", res['detection'])

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python static_detector.py /path/to/file")
        sys.exit(1)
    path = sys.argv[1]
    if not os.path.exists(path):
        print("File not found:", path)
        sys.exit(1)
    res = analyze(path)
    pretty_print(res)
