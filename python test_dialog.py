import tkinter as tk
from tkinter import filedialog

root = tk.Tk()
root.withdraw()  # Hide main window

file_path = filedialog.askopenfilename(
    title="Select Image",
    filetypes=[
        ("Image Files", ("*.png", "*.jpg", "*.jpeg")),
        ("All Files", "*.*"),
    ]
)

print("You selected:", file_path)
