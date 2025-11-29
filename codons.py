#!/usr/bin/env python3
# codons.py
# Text ⇄ DNA codons (with 1-codon header carrying pad-bit count)
# Dynamic codon mapping supported via set_key(password=None, seed=None)

from typing import List, Optional, Tuple
import hashlib
import random
import json
import argparse
import sys

# canonical bases and helper to build default codon list
_BASES = ["A", "T", "G", "C"]

def _canonical_codon_list() -> List[str]:
    """Return canonical codons in the deterministic order corresponding to bit values 0..63."""
    codons = []
    for v in range(64):
        b = f"{v:06b}"
        codon = "".join({
            "00": "A",
            "01": "T",
            "10": "G",
            "11": "C"
        }[b[i:i+2]] for i in (0, 2, 4))
        codons.append(codon)
    return codons

# module-level mapping tables (populated by set_key or default on first use)
_bits_index_to_codon: Optional[List[str]] = None  # index 0..63 -> codon (str length 3)
_codon_to_bits_index: Optional[dict] = None      # codon -> int index 0..63

def _ensure_default_mapping():
    global _bits_index_to_codon, _codon_to_bits_index
    if _bits_index_to_codon is None or _codon_to_bits_index is None:
        base = _canonical_codon_list()
        _bits_index_to_codon = base.copy()
        _codon_to_bits_index = {c: i for i, c in enumerate(_bits_index_to_codon)}

def set_key(password: Optional[str] = None, seed: Optional[int] = None) -> None:
    """
    Initialize a deterministic codon mapping from either a password (string),
    or a numeric seed (int), or both. If both provided they are combined.
    This shuffles the canonical codon list using a RNG seeded by SHA-256(password || seed).
    Call this BEFORE text_to_codons / codons_to_text to ensure consistent mapping.
    """
    global _bits_index_to_codon, _codon_to_bits_index

    if password is None and seed is None:
        # reset to default
        _ensure_default_mapping()
        return

    # Build deterministic seed bytes
    hasher = hashlib.sha256()
    if password is not None:
        if not isinstance(password, str):
            raise TypeError("password must be a string")
        hasher.update(password.encode("utf-8"))
    if seed is not None:
        if not isinstance(seed, int):
            raise TypeError("seed must be an int")
        # convert seed int to bytes in a stable way
        hasher.update(seed.to_bytes((seed.bit_length() + 7) // 8 or 1, byteorder="big"))
    digest = hasher.digest()
    # Create a deterministic RNG seeded from digest
    seed_int = int.from_bytes(digest, "big")
    rng = random.Random(seed_int)

    # Shuffle canonical codon list
    base = _canonical_codon_list()
    shuffled = base.copy()
    rng.shuffle(shuffled)

    # Populate mapping tables
    _bits_index_to_codon = shuffled
    _codon_to_bits_index = {c: i for i, c in enumerate(shuffled)}

def _bits6_to_codon(bits6: str) -> str:
    """Convert a 6-bit string into codon string using current mapping table."""
    if len(bits6) != 6:
        raise ValueError("bits6 must be length 6")
    _ensure_default_mapping()
    idx = int(bits6, 2)
    return _bits_index_to_codon[idx]

def _codon_to_bits6(codon: str) -> str:
    """Convert a codon (3 bases) into its 6-bit string using current mapping."""
    _ensure_default_mapping()
    if codon not in _codon_to_bits_index:
        raise ValueError(f"Invalid codon: {codon!r}")
    idx = _codon_to_bits_index[codon]
    return f"{idx:06b}"

def _bytes_to_bitstring(b: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in b)

def _bitstring_to_bytes(bits: str) -> bytes:
    # bits length must be multiple of 8
    if len(bits) % 8 != 0:
        raise ValueError("Bitstring length not multiple of 8")
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

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
    codons = [_bits6_to_codon(header_bits)]

    # Data codons
    for i in range(0, len(bitstr_padded), 6):
        codons.append(_bits6_to_codon(bitstr_padded[i:i+6]))

    return codons

def codons_to_text(codons: List[str]) -> str:
    """
    Decode a list of DNA codons back to UTF-8 text.
    Expects the first codon to be the header with pad-bit count.
    """
    if not codons:
        return ""

    # Header
    header_bits = _codon_to_bits6(codons[0])
    pad = int(header_bits, 2)  # 0..5

    # Data
    data_bits = "".join(_codon_to_bits6(c) for c in codons[1:])

    # Remove pad bits at the end
    if pad:
        data_bits = data_bits[:-pad]

    # Convert back to bytes/text
    data = _bitstring_to_bytes(data_bits)
    return data.decode("utf-8")

# CLI for quick tests: supports seed or password
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Text ⇄ DNA codons (seeded mapping)")
    sub = parser.add_subparsers(dest="cmd", required=False)

    pe = sub.add_parser("encode", help="Encode text to codons")
    pe.add_argument("text", help="Text to encode")
    pe.add_argument("--password", help="Password seed for mapping", default=None)
    pe.add_argument("--seed", help="Numeric seed (hex or int)", default=None)

    pd = sub.add_parser("decode", help="Decode codons to text")
    pd.add_argument("codons", nargs="*", help='Codons (e.g., AAA TGC ATG ...) or leave empty for interactive')
    pd.add_argument("--password", help="Password seed for mapping", default=None)
    pd.add_argument("--seed", help="Numeric seed (hex or int)", default=None)

    args = parser.parse_args()

    def parse_seed(s: Optional[str]) -> Optional[int]:
        if s is None:
            return None
        s = s.strip()
        try:
            # int with base 0 accepts 0x... or decimal
            return int(s, 0)
        except Exception:
            # fallback to hash of string
            return int(hashlib.sha256(s.encode()).hexdigest(), 16)

    # If no subcommand specified -> interactive demo
    if args.cmd is None:
        print("No arguments provided. Running quick demo and interactive mode.\n")
        demo = "Hello"
        print("Demo encode text:", demo)
        set_key(None, None)
        cds = text_to_codons(demo)
        print("Default demo encoding:", " ".join(cds))
        print("Decoded back:", codons_to_text(cds))
        # interactive loop
        try:
            while True:
                print("\nOptions: (e)ncode, (d)ecode, (q)uit")
                choice = input("Choose: ").strip().lower()
                if not choice:
                    continue
                if choice[0] == 'q':
                    print("Exiting.")
                    break
                elif choice[0] == 'e':
                    txt = input("Enter text to encode: ")
                    pwd = input("Password (leave empty for default): ")
                    seed_in = input("Seed (leave empty for default): ")
                    seed_val = parse_seed(seed_in) if seed_in else None
                    set_key(pwd if pwd else None, seed_val)
                    try:
                        enc = text_to_codons(txt)
                        print("Codons:", " ".join(enc))
                    except Exception as ex:
                        print("Error encoding:", ex)
                elif choice[0] == 'd':
                    s = input("Enter codons separated by spaces: ")
                    pwd = input("Password (leave empty for default): ")
                    seed_in = input("Seed (leave empty for default): ")
                    seed_val = parse_seed(seed_in) if seed_in else None
                    set_key(pwd if pwd else None, seed_val)
                    try:
                        codon_list = s.strip().split()
                        txt = codons_to_text(codon_list)
                        print("Decoded text:", txt)
                    except Exception as ex:
                        print("Decode error:", ex)
                else:
                    print("Unknown option.")
        except (KeyboardInterrupt, EOFError):
            print("\nInterrupted. Exiting.")
        sys.exit(0)

    # Otherwise behave as CLI (encode/decode)
    seed_val = parse_seed(getattr(args, "seed", None))
    pwd = getattr(args, "password", None)
    set_key(password=pwd, seed=seed_val)

    if args.cmd == "encode":
        cds = text_to_codons(args.text)
        print(" ".join(cds))
    else:
        try:
            if args.codons:
                txt = codons_to_text(args.codons)
                print(txt)
            else:
                print("No codons provided for decode.")
        except Exception as e:
            print(f"Decode error: {e}", file=sys.stderr)
            sys.exit(1)
