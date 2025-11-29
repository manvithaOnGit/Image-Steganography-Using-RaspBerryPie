# he_paillier.py
# Paillier homomorphic demo helpers (uses phe)
# Minimal, robust helpers: generate_paillier_keypair, encrypt_codon_list, decrypt_codon_bytes

import json

# Try to import the library and show a clear error if missing
try:
    from phe import paillier
except Exception as e:
    raise ImportError("phe library not available. Install with: python -m pip install phe") from e


def generate_paillier_keypair(n_length: int = 2048):
    """
    Generate a Paillier keypair and return (public_key, private_key).
    Use n_length=1024 for quick demos (not secure), 2048 recommended for better security.
    """
    public_key, private_key = paillier.generate_paillier_keypair(n_length=n_length)
    return public_key, private_key


def encrypt_codon_list(codon_list, pubkey):
    """
    Encrypt a list of codon strings (each length 3, letters A/T/G/C) using Paillier public key.
    Returns: bytes (utf-8) of JSON array of {"c": ciphertext_hex, "e": exponent}
    Each codon packed to small int 0..63 via A->0,T->1,G->2,C->3 and (b0<<4)|(b1<<2)|b2.
    """
    bmap = {"A": 0, "T": 1, "G": 2, "C": 3}
    ints = []
    for codon in codon_list:
        if not isinstance(codon, str) or len(codon) != 3:
            raise ValueError("Each codon must be a 3-character string (A/T/G/C).")
        v = (bmap[codon[0]] << 4) | (bmap[codon[1]] << 2) | bmap[codon[2]]
        ints.append(int(v))

    enc_items = []
    for x in ints:
        enc = pubkey.encrypt(int(x))
        # store ciphertext integer as hex string and exponent separately
        enc_items.append({"c": format(enc.ciphertext(), "x"), "e": enc.exponent})
    return json.dumps(enc_items).encode("utf-8")


def decrypt_codon_bytes(enc_bytes, privkey):
    """
    Given bytes (JSON) produced by encrypt_codon_list, decrypt using private key.
    Returns: list of codon strings.
    """
    data = json.loads(enc_bytes.decode("utf-8"))
    out_codons = []
    rmap = {0: "A", 1: "T", 2: "G", 3: "C"}
    for it in data:
        c_hex = it["c"]
        e = it["e"]
        c_int = int(c_hex, 16)
        enc = paillier.EncryptedNumber(privkey.public_key, c_int, e)
        dec = privkey.decrypt(enc)  # integer 0..63
        b0 = (dec >> 4) & 0x3
        b1 = (dec >> 2) & 0x3
        b2 = dec & 0x3
        codon = rmap[b0] + rmap[b1] + rmap[b2]
        out_codons.append(codon)
    return out_codons
