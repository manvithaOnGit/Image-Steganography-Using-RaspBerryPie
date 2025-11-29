"""
he_paillier.py

Utilities to integrate Paillier homomorphic encryption into a stego pipeline.

Features:
- Key generation (Paillier)
- Packing/unpacking of 6-bit symbols into k-wide integers
- Encrypt + serialize ciphertexts into a compact bytes payload (with header)
- Deserialize + decrypt payload into 6-bit symbol sequence
- Uses bytes (int.to_bytes) for robust binary handling, not text bit-strings

Notes:
- Requires `phe` library: pip install phe
- Large ciphertexts will expand payload significantly. See warnings in functions.
- This module DOES NOT embed/extract into/from images. It returns bytes payloads
  you should pass to your LSB embed/extract routines. The header format is:
    4 bytes: magic (0xC0DEHE01)  (uint32)
    2 bytes: header length (H)   (uint16)
    H bytes: JSON header (utf-8) containing meta (pack_k, block_bytes, count, key_bits)
    remaining bytes: ciphertext blocks (count * block_bytes)
"""

import struct
import json
from phe import paillier
from typing import List, Tuple

MAGIC = 0xC0DE1BEE  # arbitrary magic number to identify our payloads


# ----------------------------
# Key generation helpers
# ----------------------------
def generate_paillier_keypair(n_length: int = 2048) -> Tuple[paillier.PaillierPublicKey, paillier.PaillierPrivateKey]:
    """
    Generate a Paillier keypair.
    n_length: key size in bits (1024, 2048 recommended for demos)
    Returns (public_key, private_key).
    """
    pubkey, privkey = paillier.generate_paillier_keypair(n_length)
    return pubkey, privkey


# ----------------------------
# Packing helpers
# ----------------------------
def pack_symbols_6bit(symbols: List[int], k: int) -> List[int]:
    """
    Pack list of 6-bit symbols (0..63) into integers, k symbols per integer.
    Example for k=4: each packed integer holds 24 bits.
    Returns list of packed integers.
    """
    if k <= 0:
        raise ValueError("k must be > 0")
    packed = []
    for i in range(0, len(symbols), k):
        group = symbols[i:i + k]
        val = 0
        for j, s in enumerate(group):
            if not (0 <= s < 64):
                raise ValueError("Symbols must be 0..63 (6-bit)")
            val |= (s & 0x3F) << (6 * j)
        packed.append(val)
    return packed


def unpack_packed_integers(packed: List[int], k: int) -> List[int]:
    """
    Unpack packed integers back into a flat list of 6-bit symbols (0..63).
    If the last packed integer contained fewer than k symbols, trailing zeros may
    be present; caller should cut to original length if known.
    """
    symbols = []
    mask = 0x3F
    for val in packed:
        for j in range(k):
            symbols.append((val >> (6 * j)) & mask)
    return symbols


# ----------------------------
# Serialization helpers
# ----------------------------
def _int_to_bytes_fixed(i: int, length_bytes: int) -> bytes:
    return i.to_bytes(length_bytes, byteorder='big', signed=False)


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big', signed=False)


# ----------------------------
# Encrypt + serialize
# ----------------------------
def encrypt_and_serialize(pubkey: paillier.PaillierPublicKey, packed_integers: List[int]) -> Tuple[bytes, dict]:
    """
    Encrypt each integer using Paillier and serialize into bytes payload.

    Returns (payload_bytes, metadata_dict) where payload_bytes contains a small header
    + ciphertext blocks.

    Metadata dict contains:
      - pack_k (not here, caller must include if needed)
      - block_bytes: number of bytes used per ciphertext integer
      - count: number of ciphertext blocks
      - key_bits: approximation of key size in bits (pubkey.n.bit_length())
    """
    # Encrypt each packed integer producing EncryptedNumber objects
    enc_objects = [pubkey.encrypt(int(m)) for m in packed_integers]

    # Extract raw ciphertext integers in a robust way:
    ciphertext_ints = []
    for enc in enc_objects:
        # phe.EncryptedNumber exposes ciphertext() in many versions; try fallback
        try:
            c_int = enc.ciphertext()
        except Exception:
            # Some versions may expose _ciphertext or ciphertext attribute
            if hasattr(enc, 'ciphertext'):
                c_int = enc.ciphertext
            elif hasattr(enc, '_ciphertext'):
                c_int = enc._ciphertext
            else:
                raise RuntimeError("Unable to extract ciphertext integer from EncryptedNumber object")
        ciphertext_ints.append(int(c_int))

    # Determine fixed byte-width to store each ciphertext integer
    max_bits = max(c.bit_length() for c in ciphertext_ints) if ciphertext_ints else 0
    block_bytes = (max_bits + 7) // 8 or 1

    # Build JSON header
    meta = {
        'block_bytes': block_bytes,
        'count': len(ciphertext_ints),
        'key_bits': pubkey.n.bit_length(),
    }
    header_json = json.dumps(meta, separators=(',', ':')).encode('utf-8')
    header_len = len(header_json)
    if header_len > 65535:
        raise ValueError("Header too large")

    # Construct binary payload: MAGIC(4) + header_len(2) + header_json + ciphertext_blocks
    out = bytearray()
    out.extend(struct.pack('>I', MAGIC))
    out.extend(struct.pack('>H', header_len))
    out.extend(header_json)

    # Append ciphertext blocks as fixed-size big-endian bytes
    for c in ciphertext_ints:
        b = _int_to_bytes_fixed(c, block_bytes)
        out.extend(b)

    return bytes(out), meta


# ----------------------------
# Deserialize + decrypt
# ----------------------------
def deserialize_and_decrypt(privkey: paillier.PaillierPrivateKey, payload: bytes) -> Tuple[List[int], dict]:
    """
    Parse payload bytes created by encrypt_and_serialize, decrypt ciphertext blocks
    and return list of packed integers.

    Returns (packed_integers_list, meta_dict)
    """
    if len(payload) < 6:
        raise ValueError("Payload too short")

    offset = 0
    magic = struct.unpack('>I', payload[offset:offset + 4])[0]; offset += 4
    if magic != MAGIC:
        raise ValueError("Invalid payload magic")

    header_len = struct.unpack('>H', payload[offset:offset + 2])[0]; offset += 2
    header_json = payload[offset:offset + header_len]; offset += header_len
    meta = json.loads(header_json.decode('utf-8'))
    block_bytes = int(meta['block_bytes'])
    count = int(meta['count'])

    expected_bytes = block_bytes * count
    if len(payload) - offset < expected_bytes:
        raise ValueError("Payload incomplete for expected ciphertext blocks")

    packed = []
    for i in range(count):
        block = payload[offset:offset + block_bytes]; offset += block_bytes
        c_int = _bytes_to_int(block)
        # Re-wrap as EncryptedNumber and decrypt
        enc_obj = paillier.EncryptedNumber(privkey.public_key, c_int)
        m = privkey.decrypt(enc_obj)
        packed.append(int(m))
    return packed, meta


# ----------------------------
# Convenience wrappers for full flow
# ----------------------------
def encode_plaintext_with_he(pubkey: paillier.PaillierPublicKey, symbols_6bit: List[int], pack_k: int = 4) -> Tuple[bytes, dict]:
    """
    Given list of 6-bit symbols (0..63), pack them, encrypt, and return payload bytes + meta.

    pack_k controls how many 6-bit symbols are grouped into one integer before encryption.
    """
    if pack_k <= 0:
        raise ValueError("pack_k must be positive integer")
    packed = pack_symbols_6bit(symbols_6bit, pack_k)
    payload_bytes, meta = encrypt_and_serialize(pubkey, packed)
    # augment meta with pack_k so caller knows how to unpack later
    meta['pack_k'] = pack_k
    meta['original_symbols_len'] = len(symbols_6bit)
    return payload_bytes, meta


def decode_payload_with_he(privkey: paillier.PaillierPrivateKey, payload: bytes, pack_k: int = None) -> Tuple[List[int], dict]:
    """
    Given payload bytes, decrypt and unpack to obtain the list of 6-bit symbols.

    If pack_k not given, function will try to read it from meta (if present).
    Returns (symbols_list, meta)
    """
    packed_list, meta = deserialize_and_decrypt(privkey, payload)
    if pack_k is None:
        # Some callers might have added pack_k into meta at creation time
        pack_k = meta.get('pack_k', None)
    if pack_k is None:
        raise ValueError("pack_k required to unpack symbols (provide as argument or embed into meta)")

    symbols = unpack_packed_integers(packed_list, pack_k)
    # If original symbol count was stored in meta, trim to it
    orig_len = meta.get('original_symbols_len', None)
    if orig_len is not None:
        symbols = symbols[:orig_len]
    meta['unpacked_symbols_len'] = len(symbols)
    return symbols, meta


# ----------------------------
# Example usage CLI-friendly
# ----------------------------
if __name__ == "__main__":
    # Demo example of encoding and decoding a short message
    pub, priv = generate_paillier_keypair(1024)  # demo key size
    message = "HELLO"
    # --- Replace these two functions with your own 6-bit mapping logic ---
    def msg_to_6bit_simple(msg):
        return [ord(c) & 0x3F for c in msg]  # simplistic truncation demo
    def symbols_to_msg_simple(symbols):
        return ''.join(chr(s) for s in symbols)

    symbols = msg_to_6bit_simple(message)
    print("Original 6-bit symbols:", symbols)

    pack_k = 4
    payload, meta = encode_plaintext_with_he(pub, symbols, pack_k=pack_k)
    print("Payload size (bytes):", len(payload), "meta:", meta)

    # Normally you'd embed 'payload' into image LSB. Here we immediately decrypt:
    recovered_symbols, meta_out = decode_payload_with_he(priv, payload, pack_k=pack_k)
    print("Recovered symbols:", recovered_symbols)
    recovered_msg = symbols_to_msg_simple(recovered_symbols)
    print("Recovered message:", recovered_msg)
