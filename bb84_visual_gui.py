# bb84_visual_gui.py
import codons
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ttkbootstrap as tb
import numpy as np
import secrets
import hashlib
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def random_bits(n, rng):
    return rng.integers(0, 2, size=n, dtype=np.uint8)

def prepare_alice(n_bits, rng):
    bits = random_bits(n_bits, rng)
    bases = random_bits(n_bits, rng)
    return bits, bases

def intercept_resend_channel(alice_bits, alice_bases, bob_bases, rng, p_eve=0.0, channel_error_rate=0.0):
    n = len(alice_bits)
    bob_results = np.empty(n, dtype=np.uint8)
    eve_mask = rng.random(n) < p_eve
    for i in range(n):
        if eve_mask[i]:
            eve_basis = rng.integers(0, 2)
            if eve_basis == alice_bases[i]:
                eve_bit = alice_bits[i]
            else:
                eve_bit = rng.integers(0, 2)
            if bob_bases[i] == eve_basis:
                measured = eve_bit
            else:
                measured = rng.integers(0, 2)
        else:
            if bob_bases[i] == alice_bases[i]:
                measured = alice_bits[i]
            else:
                measured = rng.integers(0, 2)
        if rng.random() < channel_error_rate:
            measured ^= 1
        bob_results[i] = measured
    return bob_results

def sift(alice_bases, bob_bases, alice_bits, bob_bits):
    match = alice_bases == bob_bases
    indices = np.nonzero(match)[0]
    return indices, alice_bits[indices], bob_bits[indices]

def estimate_qber(alice_sift_bits, bob_sift_bits, sample_fraction, rng):
    n = len(alice_sift_bits)
    sample_count = max(1, int(np.ceil(n * sample_fraction)))
    if sample_count > n:
        sample_count = n
    sampled_positions = rng.choice(n, size=sample_count, replace=False).tolist()
    errors = sum(int(alice_sift_bits[i] != bob_sift_bits[i]) for i in sampled_positions)
    qber = errors / sample_count if sample_count > 0 else 0.0
    return qber, sampled_positions, errors

def error_reconciliation_parity(alice_sift_bits, bob_sift_bits, block_size, rng):
    n = len(alice_sift_bits)
    alice = alice_sift_bits.copy()
    bob = bob_sift_bits.copy()
    def parity_of(arr, idxs):
        if len(idxs) == 0:
            return 0
        return int(np.bitwise_xor.reduce(arr[idxs]))
    for start in range(0, n, block_size):
        end = min(n, start + block_size)
        idxs = list(range(start, end))
        a_par = parity_of(alice, idxs)
        b_par = parity_of(bob, idxs)
        if a_par != b_par:
            lo, hi = start, end
            while hi - lo > 1:
                mid = (lo + hi) // 2
                left_idxs = list(range(lo, mid))
                if parity_of(alice, left_idxs) != parity_of(bob, left_idxs):
                    hi = mid
                else:
                    lo = mid
            bob[lo] ^= 1
    return alice, bob

def privacy_amplification(shared_bits, final_key_len, rng):
    n = len(shared_bits)
    if final_key_len <= 0 or final_key_len > n:
        raise ValueError("final_key_len must be between 1 and length of shared bits")
    R = rng.integers(0, 2, size=(final_key_len, n), dtype=np.uint8)
    out = (R @ shared_bits) % 2
    return out.astype(np.uint8)

def run_bb84_sim(n_bits=1024, p_eve=0.02, channel_error_rate=0.01, sample_fraction=0.05, block_size=16, final_key_len=128, rng_seed=None):
    rng = np.random.default_rng(rng_seed if rng_seed is not None else secrets.randbits(32))
    alice_bits, alice_bases = prepare_alice(n_bits, rng)
    bob_bases = random_bits(n_bits, rng)
    bob_results = intercept_resend_channel(alice_bits, alice_bases, bob_bases, rng, p_eve=p_eve, channel_error_rate=channel_error_rate)
    indices, alice_sifted, bob_sifted = sift(alice_bases, bob_bases, alice_bits, bob_results)
    n_sifted = len(indices)
    qber_est, sample_positions, sample_errors = estimate_qber(alice_sifted, bob_sifted, sample_fraction, rng)
    mask = np.ones(n_sifted, dtype=bool)
    mask[sample_positions] = False
    alice_after_sample = alice_sifted[mask]
    bob_after_sample = bob_sifted[mask]
    alice_corrected, bob_corrected = error_reconciliation_parity(alice_after_sample, bob_after_sample, block_size, rng)
    matching_mask = alice_corrected == bob_corrected
    shared_bits = alice_corrected[matching_mask]
    success = len(shared_bits) >= final_key_len
    final_key_bits = None
    final_key_hex = None
    if success:
        pa_rng = np.random.default_rng(rng.integers(0, 2**32))
        final_key_bits = privacy_amplification(shared_bits, final_key_len, pa_rng)
        final_key_str = ''.join(str(int(b)) for b in final_key_bits)
        final_key_hex = hex(int(final_key_str, 2))[2:]
    return {
        'alice_bits': alice_bits,
        'alice_bases': alice_bases,
        'bob_bases': bob_bases,
        'bob_results': bob_results,
        'indices': indices,
        'alice_sifted': alice_sifted,
        'bob_sifted': bob_sifted,
        'qber_est': qber_est,
        'sample_positions': sample_positions,
        'sample_errors': sample_errors,
        'shared_bits': shared_bits,
        'final_key_hex': final_key_hex,
        'final_key_bits': final_key_bits,
        'success': success,
        'n_sifted': n_sifted,
    }

class BB84GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BB84 QKD Visualizer")
        self.style = tb.Style(theme='litera')
        self.mainframe = ttk.Frame(root, padding=10)
        self.mainframe.pack(fill='both', expand=True)
        self._make_controls()
        self._make_plots()
        self.last_result = None

    def _make_controls(self):
        ctrl = ttk.LabelFrame(self.mainframe, text='Controls', padding=8)
        ctrl.grid(row=0, column=0, sticky='nsew')
        ttk.Label(ctrl, text='Number of qubits:').grid(row=0, column=0, sticky='w')
        self.n_bits_var = tk.IntVar(value=2048)
        ttk.Entry(ctrl, textvariable=self.n_bits_var, width=8).grid(row=0, column=1, sticky='w')
        ttk.Label(ctrl, text='Eve intercept prob:').grid(row=1, column=0, sticky='w')
        self.p_eve_var = tk.DoubleVar(value=0.02)
        ttk.Entry(ctrl, textvariable=self.p_eve_var, width=8).grid(row=1, column=1, sticky='w')
        ttk.Label(ctrl, text='Channel error rate:').grid(row=2, column=0, sticky='w')
        self.chan_err_var = tk.DoubleVar(value=0.01)
        ttk.Entry(ctrl, textvariable=self.chan_err_var, width=8).grid(row=2, column=1, sticky='w')
        ttk.Label(ctrl, text='Sample fraction:').grid(row=3, column=0, sticky='w')
        self.sample_frac_var = tk.DoubleVar(value=0.05)
        ttk.Entry(ctrl, textvariable=self.sample_frac_var, width=8).grid(row=3, column=1, sticky='w')
        ttk.Label(ctrl, text='Final key length (bits):').grid(row=4, column=0, sticky='w')
        self.final_len_var = tk.IntVar(value=256)
        ttk.Entry(ctrl, textvariable=self.final_len_var, width=8).grid(row=4, column=1, sticky='w')

        run_btn = tb.Button(ctrl, text='Run Simulation', bootstyle='success', command=self.run_simulation)
        run_btn.grid(row=5, column=0, columnspan=2, pady=6)

        save_btn = tb.Button(ctrl, text='Save Key', bootstyle='info', command=self.save_key)
        save_btn.grid(row=6, column=0, columnspan=2, pady=2)

        self.use_qkd_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctrl, text='Use QKD key for codon mapping', variable=self.use_qkd_var).grid(row=7, column=0, columnspan=2, sticky='w', pady=(4,0))

        apply_btn = tb.Button(ctrl, text='Apply QKD Key → Mapping', bootstyle='primary', command=self.apply_qkd_key)
        apply_btn.grid(row=8, column=0, columnspan=2, pady=(6,0))

        copy_btn = tb.Button(ctrl, text='Copy Key', bootstyle='secondary', command=self.copy_key_to_clipboard)
        copy_btn.grid(row=9, column=0, columnspan=2, pady=(2,0))

        self.status_lbl = ttk.Label(ctrl, text='Status: idle')
        self.status_lbl.grid(row=10, column=0, columnspan=2, sticky='w', pady=(6,0))

    def apply_qkd_key(self):
        if not self.last_result or not self.last_result.get('success'):
            messagebox.showwarning('No key', 'No final key available. Run simulation first.')
            return
        if not self.use_qkd_var.get():
            messagebox.showinfo('Not enabled', 'The "Use QKD key" checkbox is not checked.')
            return
        hexkey = self.last_result.get('final_key_hex')
        if not hexkey:
            messagebox.showerror('Error', 'No valid key found in last result.')
            return
        try:
            seed_int = int(hexkey, 16)
        except Exception:
            seed_int = int(hashlib.sha256(hexkey.encode()).hexdigest(), 16)
        codons.set_key(seed=seed_int)
        messagebox.showinfo('Applied', 'QKD key applied to codon mapping (local).')

    def copy_key_to_clipboard(self):
        if not self.last_result or not self.last_result.get('success'):
            messagebox.showwarning('No key', 'No final key available to copy.')
            return
        hexkey = self.last_result.get('final_key_hex')
        if not hexkey:
            messagebox.showerror('Error', 'No valid key found in last result.')
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(hexkey)
            messagebox.showinfo('Copied', 'QKD key copied to clipboard (hex).')
        except Exception as e:
            messagebox.showerror('Clipboard error', f'Failed to copy to clipboard: {e}')

    def _make_plots(self):
        plot_frame = ttk.LabelFrame(self.mainframe, text='Visualization', padding=8)
        plot_frame.grid(row=0, column=1, sticky='nsew')
        self.fig = Figure(figsize=(8,4))
        self.ax_raster = self.fig.add_subplot(121)
        self.ax_qber = self.fig.add_subplot(122)
        self.ax_raster.set_title('Bits / Bases (raster)')
        self.ax_qber.set_title('QBER (sample)')
        self.fig.tight_layout()
        self.canvas = FigureCanvasTkAgg(self.fig, master=plot_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)

        info_frame = ttk.LabelFrame(self.mainframe, text='Result Info', padding=8)
        info_frame.grid(row=1, column=0, columnspan=2, sticky='nsew', pady=(8,0))
        self.info_text = tk.Text(info_frame, height=8, wrap='word')
        self.info_text.pack(fill='both', expand=True)

    def run_simulation(self):
        self.status_lbl.config(text='Status: running...')
        n_bits = max(64, int(self.n_bits_var.get()))
        p_eve = float(self.p_eve_var.get())
        chan_err = float(self.chan_err_var.get())
        sample_frac = float(self.sample_frac_var.get())
        final_len = int(self.final_len_var.get())
        res = run_bb84_sim(n_bits=n_bits, p_eve=p_eve, channel_error_rate=chan_err, sample_fraction=sample_frac, final_key_len=final_len)
        self.last_result = res
        self._update_visuals(res)
        self._update_info(res)
        self.status_lbl.config(text='Status: done')

    def _update_visuals(self, res):
        show_n = min(200, len(res['alice_bits']))
        matrix = np.vstack([
            res['alice_bits'][:show_n],
            res['alice_bases'][:show_n],
            res['bob_bases'][:show_n],
            res['bob_results'][:show_n]
        ])
        self.ax_raster.clear()
        self.ax_raster.imshow(matrix, aspect='auto', interpolation='nearest')
        self.ax_raster.set_yticks([0,1,2,3])
        self.ax_raster.set_yticklabels(['A bits','A bases','B bases','B meas'])
        self.ax_raster.set_xlabel('Position (first %d)' % show_n)

        self.ax_qber.clear()
        q = res['qber_est']
        samp_errs = res['sample_errors']
        samp_n = len(res['sample_positions'])
        self.ax_qber.bar([0], [q*100])
        self.ax_qber.set_ylim(0, max(5, q*100*3))
        self.ax_qber.set_xticks([0])
        self.ax_qber.set_xticklabels([f'QBER sample ({samp_n})'])
        self.ax_qber.set_ylabel('% errors')
        self.fig.tight_layout()
        self.canvas.draw()

    def _update_info(self, res):
        self.info_text.delete('1.0', tk.END)
        lines = []
        lines.append(f"Sifted bits: {res['n_sifted']}")
        lines.append(f"Estimated QBER (sample): {res['qber_est']*100:.3f}% ({res['sample_errors']} errors in {len(res['sample_positions'])} sampled)")
        lines.append(f"Shared bits available: {len(res['shared_bits'])}")
        if res['success']:
            lines.append(f"FINAL KEY (hex): {res['final_key_hex']}")
        else:
            lines.append("FINAL KEY: <not enough bits to produce requested key length>")
        self.info_text.insert(tk.END, '\n'.join(lines))

    def save_key(self):
        if not self.last_result or not self.last_result.get('success'):
            messagebox.showwarning('No key', 'No final key available to save. Run simulation first and ensure success.')
            return
        initial = 'qkd_key.txt'
        path = filedialog.asksaveasfilename(defaultextension='.txt', initialfile=initial, filetypes=[('Text files','*.txt')])
        if not path:
            return
        with open(path, 'w') as f:
            f.write(self.last_result['final_key_hex'])
        messagebox.showinfo('Saved', f'Key saved to: {path}')

if __name__ == "__main__":
    root = tb.Window(themename='litera')
    app = BB84GUI(root)
    root.mainloop()
