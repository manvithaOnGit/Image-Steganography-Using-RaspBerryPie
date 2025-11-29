from PIL import Image
import sys
from codons import text_to_codons, codons_to_text, set_key

def encode_image(infile, outfile, text):
    codons = text_to_codons(text)
    data = " ".join(codons).encode("utf-8")

    # Store message length (in bytes) as 32-bit header
    length = len(data)
    header = length.to_bytes(4, "big")
    payload = header + data

    bits = ''.join(f"{b:08b}" for b in payload)

    img = Image.open(infile).convert("RGB")
    pixels = list(img.getdata())
    cap = len(pixels) * 3
    if len(bits) > cap:
        raise ValueError("Message too long for this image.")

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
    img.save(outfile)
    print(f"Encoded {len(codons)} codons into {outfile}")

def decode_image(infile):
    img = Image.open(infile).convert("RGB")
    pixels = list(img.getdata())
    bits = ""
    for r,g,b in pixels:
        bits += str(r & 1)
        bits += str(g & 1)
        bits += str(b & 1)

    # First 32 bits = length of message
    msg_len = int(bits[:32], 2)
    data_bits = bits[32:32 + msg_len*8]

    data = bytes(int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8))
    s = data.decode("utf-8", errors="ignore")
    codons = s.strip().split()
    if codons:
        return codons, codons_to_text(codons)
    return None, None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  Encode: python stego_image.py encode cover.png stego.png 'Message' [password]")
        print("  Decode: python stego_image.py decode stego.png [password]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "encode":
        infile, outfile, text = sys.argv[2], sys.argv[3], sys.argv[4]
        pwd = sys.argv[5] if len(sys.argv) > 5 else ""
        set_key(pwd)
        encode_image(infile, outfile, text)
    elif cmd == "decode":
        infile = sys.argv[2]
        pwd = sys.argv[3] if len(sys.argv) > 3 else ""
        set_key(pwd)
        codons, msg = decode_image(infile)
        if codons:
            print("Codons:", " ".join(codons))
            print("Message:", msg)
        else:
            print("Decode failed.")
