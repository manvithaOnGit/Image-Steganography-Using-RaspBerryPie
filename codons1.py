
# codons.py
# Text ⇄ DNA codons (with 1-codon header carrying pad-bit count)
# Mapping: 00→A, 01→T, 10→G, 11→C

from typing import List
import sys


# 2-bit → base and inverse
BITS_TO_BASE = {"00": "A", "01": "T", "10": "G", "11": "C"}
BASE_TO_BITS = {v: k for k, v in BITS_TO_BASE.items()}

def _bytes_to_bitstring(b: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in b)

def _bitstring_to_bytes(bits: str) -> bytes:
    # bits length must be multiple of 8
    if len(bits) % 8 != 0:
        raise ValueError("Bitstring length not multiple of 8")
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def _bits_to_codon(bits6: str) -> str:
    # bits6 must be exactly 6 bits
    return (
        BITS_TO_BASE[bits6[0:2]] +
        BITS_TO_BASE[bits6[2:4]] +
        BITS_TO_BASE[bits6[4:6]]
    )

def _codon_to_bits(codon: str) -> str:
    if len(codon) != 3 or any(c not in BASE_TO_BITS for c in codon):
        raise ValueError(f"Invalid codon: {codon!r}")
    return BASE_TO_BITS[codon[0]] + BASE_TO_BITS[codon[1]] + BASE_TO_BITS[codon[2]]

def text_to_codons(text: str) -> List[str]:
    """
    Encode UTF-8 text to a list of DNA codons (strings of length 3).
    The first codon is a header that stores the number of pad bits (0..5).
    """
    data = text.encode("utf-8")
    bitstr = _bytes_to_bitstring(data)

    # Pad to multiple of 6 bits (codon = 6 bits)
    pad = (6 - (len(bitstr) % 6)) % 6
    if pad:
        bitstr_padded = bitstr + ("0" * pad)
    else:
        bitstr_padded = bitstr

    # Header: store pad (0..5) in 6 bits
    header_bits = f"{pad:06b}"
    codons = [_bits_to_codon(header_bits)]

    # Data codons
    for i in range(0, len(bitstr_padded), 6):
        codons.append(_bits_to_codon(bitstr_padded[i:i+6]))

    return codons

def codons_to_text(codons: List[str]) -> str:
    """
    Decode a list of DNA codons back to UTF-8 text.
    Expects the first codon to be the header with pad-bit count.
    """
    if not codons:
        return ""

    # Header
    header_bits = _codon_to_bits(codons[0])
    pad = int(header_bits, 2)  # 0..5

    # Data
    data_bits = "".join(_codon_to_bits(c) for c in codons[1:])

    # Remove pad bits at the end
    if pad:
        data_bits = data_bits[:-pad]

    # Convert back to bytes/text
    data = _bitstring_to_bytes(data_bits)
    return data.decode("utf-8")


# --------- Simple CLI for quick tests ----------
if __name__ == "__main__":
    import argparse, sys

    parser = argparse.ArgumentParser(description="Text ⇄ DNA codons")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("encode", help="Encode text to codons")
    pe.add_argument("text", help="Text to encode")

    pd = sub.add_parser("decode", help="Decode codons to text")
    pd.add_argument("codons", nargs="+", help='Codons (e.g., AAA TGC ATG ...)')

    args = parser.parse_args()

    if args.cmd == "encode":
        cds = text_to_codons(args.text)
        # Print space-separated codons for readability
        print(" ".join(cds))
    else:
        try:
            txt = codons_to_text(args.codons)
            print(txt)
        except Exception as e:
            print(f"Decode error: {e}", file=sys.stderr)
            sys.exit(1)

# Add this if not already present
import hashlib

def keyed_mapping(password: str):
    bases = ['A','T','G','C']
    h = hashlib.sha256(password.encode('utf-8')).digest()
    bases_perm = bases[:]
    for i in range(len(bases_perm)-1, 0, -1):
        j = h[i] % (i+1)
        bases_perm[i], bases_perm[j] = bases_perm[j], bases_perm[i]
    two_bits = ['00','01','10','11']
    BITS_TO_BASE = {b: bases_perm[i] for i, b in enumerate(two_bits)}
    BASE_TO_BITS = {v: k for k, v in BITS_TO_BASE.items()}
    return BITS_TO_BASE, BASE_TO_BITS

def set_key(password: str):
    global BITS_TO_BASE, BASE_TO_BITS
    BITS_TO_BASE, BASE_TO_BITS = keyed_mapping(password)