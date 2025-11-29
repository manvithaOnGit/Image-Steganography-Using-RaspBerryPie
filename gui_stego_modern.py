import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from PIL import Image
from codons import text_to_codons, codons_to_text, set_key
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import simpledialog

# ===== Stego helpers =====
def encode_into_image(cover_path, out_path, message, password=""):
    set_key(password)
    codons = text_to_codons(message)
    data = " ".join(codons).encode("utf-8")
    length = len(data)
    header = length.to_bytes(4, "big")
    payload = header + data
    bits = ''.join(f"{b:08b}" for b in payload)

    img = Image.open(cover_path).convert("RGB")
    pixels = list(img.getdata())
    cap = len(pixels) * 3
    if len(bits) > cap:
        raise ValueError("Message too long for this image!")

    new_pixels, idx = [], 0
    for r,g,b in pixels:
        rgb = [r,g,b]
        for c in range(3):
            if idx < len(bits):
                rgb[c] = (rgb[c] & ~1) | int(bits[idx])
                idx += 1
        new_pixels.append(tuple(rgb))
    img.putdata(new_pixels)
    img.save(out_path)
    return codons

def decode_from_image(stego_path, password=""):
    set_key(password)
    img = Image.open(stego_path).convert("RGB")
    pixels = list(img.getdata())
    bits = "".join(str(ch & 1) for px in pixels for ch in px)

    msg_len = int(bits[:32], 2)
    data_bits = bits[32:32 + msg_len*8]
    data = bytes(int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8))
    s = data.decode("utf-8", errors="ignore")
    codons = s.strip().split()
    return codons, codons_to_text(codons)

# ===== GUI =====
app = ttk.Window(themename="cyborg")  # High-contrast dark theme
app.title("🧬 DNA Codon Steganography")
app.geometry("800x710")

# Title label
ttk.Label(app, text="DNA Codon Steganography Tool", font=("Segoe UI", 18, "bold"), bootstyle=INFO).pack(pady=10)

# Message input
msg_label = ttk.Label(app, text="Enter Message:", font=("Segoe UI", 12, "bold"))
msg_label.pack(anchor="w", padx=20)
msg_entry = ScrolledText(app, width=80, height=4, font=("Consolas", 11))
msg_entry.pack(padx=20, pady=6)

# Password
pwd_frame = ttk.Frame(app)
pwd_frame.pack(fill="x", padx=20, pady=10)
ttk.Label(pwd_frame, text="🔐 Password (optional):", font=("Segoe UI", 11)).pack(side="left")
pwd_entry = ttk.Entry(pwd_frame, show="*", width=30)
pwd_entry.pack(side="left", padx=10)

# Codon display
ttk.Label(app, text="Generated Codons:", font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=20)
codon_box = ScrolledText(app, width=80, height=4, font=("Consolas", 11), fg="cyan", bg="black")
codon_box.pack(padx=20, pady=6)

# Decoded output
ttk.Label(app, text="Decoded Message:", font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=20)
decoded_box = ScrolledText(app, width=80, height=4, font=("Consolas", 11), fg="lime", bg="black")
decoded_box.pack(padx=20, pady=6)

cover_path, stego_path = tk.StringVar(), tk.StringVar()

def choose_cover():
    path = filedialog.askopenfilename(
        title="Select Cover Image",
        filetypes=[
            ("Image Files", ("*.png", "*.jpg", "*.jpeg", "*.webp")),
            ("PNG Files", "*.png"),
            ("JPEG Files", ("*.jpg", "*.jpeg")),
            ("All Files", "*.*"),
        ]
    )
    if path:
        # --- Auto-convert if not PNG ---
        if not path.lower().endswith(".png"):
            try:
                img = Image.open(path).convert("RGB")
                newpath = os.path.splitext(path)[0] + ".png"
                img.save(newpath)
                messagebox.showinfo("Converted", f"Non-PNG image converted to {newpath}")
                path = newpath
            except Exception as e:
                messagebox.showerror("Error", f"Could not open/convert file: {e}")
                return
        cover_path.set(path)

def save_stego():
    path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Images","*.png")])
    if path: stego_path.set(path)

def do_encode():
    try:
        if not cover_path.get():
            messagebox.showerror("Error","Choose a cover image first")
            return
        if not stego_path.get():
            messagebox.showerror("Error","Choose where to save stego image")
            return
        msg = msg_entry.get("1.0","end-1c")
        pwd = pwd_entry.get()
        codons = encode_into_image(cover_path.get(), stego_path.get(), msg, pwd)
        codon_box.delete("1.0","end")
        codon_box.insert("1.0", " ".join(codons))
        messagebox.showinfo("Success", f"Message hidden in {os.path.basename(stego_path.get())}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def do_decode():
    try:
        path = filedialog.askopenfilename(
            title="Select Stego Image",
            filetypes=[("Image Files", ("*.png", "*.jpg", "*.jpeg", "*.webp")), ("All Files","*.*")]
        )
        if not path: return
        # Auto-convert if not PNG
        if not path.lower().endswith(".png"):
            try:
                img = Image.open(path).convert("RGB")
                newpath = os.path.splitext(path)[0] + ".png"
                img.save(newpath)
                messagebox.showinfo("Converted", f"Non-PNG stego image converted to {newpath}")
                path = newpath
            except Exception as e:
                messagebox.showerror("Error", f"Could not open/convert file: {e}")
                return

        # Ask password each time
        pwd = simpledialog.askstring("Password", "Enter password for decoding:", show="*")
        if pwd is None: pwd = ""  # Cancel → blank password
        codons, msg = decode_from_image(path, pwd)
        codon_box.delete("1.0","end")
        codon_box.insert("1.0", " ".join(codons))
        decoded_box.delete("1.0","end")
        decoded_box.insert("1.0", msg)
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Buttons row
btn_frame = ttk.Frame(app)
btn_frame.pack(pady=20)

ttk.Button(btn_frame, text="📂 Choose Cover Image", command=choose_cover, bootstyle=PRIMARY).grid(row=0, column=0, padx=10)
ttk.Button(btn_frame, text="💾 Save Stego As...", command=save_stego, bootstyle=SECONDARY).grid(row=0, column=1, padx=10)
ttk.Button(btn_frame, text="🧬 Encode", command=do_encode, bootstyle=SUCCESS).grid(row=0, column=2, padx=10)
ttk.Button(btn_frame, text="🔎 Decode from Image", command=do_decode, bootstyle=WARNING).grid(row=0, column=3, padx=10)

app.mainloop()
