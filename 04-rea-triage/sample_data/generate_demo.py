#!/usr/bin/env python3
"""Generate sample_data/synthetic_demo.elf — a minimal synthetic ELF64.

NOT malware: a hand-built ELF header plus a high-entropy .text section
(deterministic pseudo-random bytes) and planted IOC strings, so
``triage.py`` has something to flag on any OS (macOS has no /bin/ls ELF).

Run:  python sample_data/generate_demo.py
Then: python triage.py sample_data/synthetic_demo.elf --output report.md
Expect: verdict=malicious (score 11, 6 findings).
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))

# Deterministic pseudo-random payload: entropy ~8.0 bits/byte, trips H1.
random_payload = bytes((i * 1103515245 + 12345) % 256 for i in range(8192))
# Planted IOC strings: trips H4 (ipv4, suspicious_url, suspicious_path).
strings_blob = b"\x00hello-triage\x00http://10.99.99.99:8080/beacon\x00/etc/shadow\x00"
text_data = random_payload + strings_blob

shstrtab = b"\x00.text\x00.shstrtab\x00"

ehsize = 64
text_off = ehsize
shstr_off = text_off + len(text_data)
shdr_off = (shstr_off + len(shstrtab) + 15) // 16 * 16  # align 16

e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
ehdr = e_ident + struct.pack(
    "<HHIQQQIHHHHHH",
    2,        # e_type: ET_EXEC
    62,       # e_machine: EM_X86_64
    1,        # e_version
    0x400000, # e_entry
    0,        # e_phoff (no program headers)
    shdr_off, # e_shoff
    0,        # e_flags
    64,       # e_ehsize
    56, 0,    # e_phentsize, e_phnum
    64, 3, 2, # e_shentsize, e_shnum, e_shstrndx
)


def shdr(name, stype, flags, addr, off, size):
    return struct.pack("<IIQQQQIIQQ", name, stype, flags, addr, off, size, 0, 0, 16, 0)


blob = ehdr + text_data + shstrtab
blob += b"\x00" * (shdr_off - len(blob))
blob += (
    shdr(0, 0, 0, 0, 0, 0)                                   # null
    + shdr(1, 1, 0x6, 0x400000, text_off, len(text_data))     # .text PROGBITS
    + shdr(7, 3, 0, 0, shstr_off, len(shstrtab))              # .shstrtab STRTAB
)

out = os.path.join(HERE, "synthetic_demo.elf")
with open(out, "wb") as f:
    f.write(blob)
print(f"wrote {out} ({len(blob)} bytes)")
