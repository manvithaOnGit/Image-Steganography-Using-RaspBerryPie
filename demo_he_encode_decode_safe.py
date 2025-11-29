
# demo_he_encode_decode_safe.py
import os
import sys
from PIL import Image

# try import HE helpers & codons; print friendly errors if missing
try:
    from he_paillier import generate_paillier_keypair, encrypt_codon_list, decrypt_codon_bytes
except Exception as e:
    print("Error importing he_paillier module. Make sure he_paillier.py is in the same folder.")
    print("If you haven't installed 'phe', run: python -m pip install phe")
    print("Import error detail:", e)
    sys.exit(1)

try:
    from codons import text_to_codons, codons_to_text, set_key
except Exception as e:
    print("Error importing codons module. Make sure codons.py is in the same folder.")
    print("Import error detail:", e)
    sys.exit(1)

def ask_for_cover(default_name="cover.png"):
    if os.path.exists(default_name):
        return default_name
    print(f"Default cover image '{default_name}' not found in folder: {os.getcwd()}")
    p = input("Enter path to a cover image (PNG/JPG) or press Enter to cancel: ").strip()
    if not p:
        print("No cover selected. Exiting.")
        sys.exit(1)
    if not os.path.exists(p):
        print("Provided path does not exist:", p)
        sys.exit(1)
    # auto-convert to PNG if needed
    if not p.lower().endswith(".png"):
        print("Converting input to PNG...")
        try:
            img = Image.open(p).convert("RGB")
            base = os.path.splitext(os.path.basename(p))[0]
            newp = os.path.join(os.getcwd(), base + ".png")
            img.save(newp)
            print("Saved converted PNG as:", newp)
            return newp
        except Exception as ex:
            print("Conversion failed:", ex)
            sys.exit(1)
    return p

def embed_payload_into_image(cover_path, out_path, payload_bytes):
    img = Image.open(cover_path).convert("RGB")
    pixels = list(img.getdata())
    cap = len(pixels) * 3  # bits
    bits = ''.join(f"{b:08b}" for b in payload_bytes)
    if len(bits) > cap:
        raise ValueError(f"Payload too large for cover image: need {len(bits)} bits, capacity {cap} bits")
    new_pixels = []
    idx = 0
    for r,g,b in pixels:
        rgb = [r,g,b]
        for c in range(3):
            if idx < len(bits):
                rgb[c] = (rgb[c] & ~1) | int(bits[idx])
                idx += 1
        new_pixels.append(tuple(rgb))
    img.putdata(new_pixels)
    img.save(out_path)
    return out_path

def extract_payload_from_image(stego_path):
    img = Image.open(stego_path).convert("RGB")
    pixels = list(img.getdata())
    bits = "".join(str(ch & 1) for px in pixels for ch in px)
    # first 32 bits = length (bytes)
    msg_len = int(bits[:32], 2)
    data_bits = bits[32:32 + msg_len * 8]
    payload_bytes = bytes(int(data_bits[i:i+8],2) for i in range(0, len(data_bits), 8))
    return payload_bytes

def main():
    cover = ask_for_cover("cover.png")
    out = "stego_he.png"
    password = input("Enter password to set mapping (or press Enter for default): ").strip()
    set_key(password if password else None)  # optional mapping
    text = input("Enter the short message to hide (keep it short for demo): ").strip()
    if not text:
        print("Empty message. Exiting.")
        return

    print("Generating Paillier keypair (this may take 1-3s)...")
    pub, priv = generate_paillier_keypair(n_length=1024)

    print("Converting message to codons...")
    codons = text_to_codons(text)
    print("Codons (first 20 shown):", " ".join(codons[:20]), "..." if len(codons)>20 else "")

    print("Encrypting codons with Paillier...")
    enc_bytes = encrypt_codon_list(codons, pub)
    header = len(enc_bytes).to_bytes(4, "big")
    payload = header + enc_bytes

    print(f"Embedding payload ({len(payload)} bytes) into image...")
    try:
        embed_payload_into_image(cover, out, payload)
    except Exception as ex:
        print("Embedding failed:", ex)
        sys.exit(1)

    print("Saved stego image as:", out)
    print("Now extracting payload back and decrypting...")

    payload_back = extract_payload_from_image(out)
    codons_back = decrypt_codon_bytes(payload_back, priv)
    recovered = codons_to_text(codons_back)
    print("Recovered text:", recovered)

if __name__ == "__main__":
    main()
