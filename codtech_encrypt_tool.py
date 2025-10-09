#!/usr/bin/env python3
"""
CODTECH - Advanced Encryption Tool (submission)

Features:
- AES-256 GCM authenticated encryption for files
- PBKDF2-HMAC-SHA256 key derivation (configurable iterations)
- Command-line interface and a simple Tkinter GUI
- Supports single-file encrypt/decrypt and directory (recursive) operations
- Safe file format: MAGIC(8) | salt(16) | nonce(12) | tag(16) | ciphertext

Usage examples (CLI):
  # Encrypt a file
  python codtech_encrypt_tool.py encrypt --infile secret.pdf --outfile secret.pdf.enc

  # Decrypt a file
  python codtech_encrypt_tool.py decrypt --infile secret.pdf.enc --outfile secret_recovered.pdf

  # Encrypt all files in directory (creates .enc files)
  python codtech_encrypt_tool.py encrypt-dir --indir ./to_encrypt --outdir ./enc_out

  # Run GUI
  python codtech_encrypt_tool.py gui

Security notes:
- Use a strong password. Longer and more random is better.
- Keep salt/nonce/tag stored inside the encrypted file (this script does that).
- This tool is for authorized use only — do not encrypt files you don't have permission to handle.
- For very large files or special use, consider more advanced tools and key management.

Requirements:
    pip install pycryptodome
    Python 3.8+
"""
import os
import sys
import argparse
import getpass
import struct
from pathlib import Path
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import traceback

# Optional GUI
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, scrolledtext
    GUI_AVAILABLE = True
except Exception:
    GUI_AVAILABLE = False

# === Configurable parameters ===
MAGIC = b'CT_ENC1\x00'    # 8 bytes
SALT_SIZE = 16            # bytes
NONCE_SIZE = 12           # bytes (recommended for GCM)
TAG_SIZE = 16             # bytes (GCM tag)
KEY_SIZE = 32             # 32 bytes => 256-bit AES key
PBKDF2_ITER = 200_000     # iterations for PBKDF2 (tunable; higher = slower but stronger)
CHUNK_SIZE = 64 * 1024    # read/write chunks for streaming (64 KB)

# === Utility / Crypto functions ===
def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITER, dklen: int = KEY_SIZE) -> bytes:
    """
    Derive a symmetric key from password and salt using PBKDF2-HMAC-SHA256.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    from Crypto.Hash import SHA256
    return PBKDF2(password, salt, dklen, count=iterations, hmac_hash_module=SHA256)


def encrypt_file(in_path: Path, out_path: Path, password: str, overwrite: bool=False) -> None:
    """
    Encrypt a file and write out_path. File format:
    [MAGIC (8)] [salt (16)] [nonce (12)] [tag (16)] [ciphertext...]
    """
    if out_path.exists() and not overwrite:
        raise FileExistsError(f"Output file {out_path} exists. Use --overwrite to overwrite.")

    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    with in_path.open('rb') as fin, out_path.open('wb') as fout:
        # write header
        fout.write(MAGIC)
        fout.write(salt)
        fout.write(nonce)
        # encrypt stream
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = cipher.encrypt(chunk)
            fout.write(ct)
        # finalize and write tag
        tag = cipher.digest()
        fout.write(tag)
    # Success
    return


def decrypt_file(in_path: Path, out_path: Path, password: str, overwrite: bool=False) -> None:
    """
    Decrypt a file created by encrypt_file. Expects same format.
    Reads header, derives key, decrypts and verifies tag at the end.
    Note: tag is stored at the end of file after ciphertext.
    """
    if out_path.exists() and not overwrite:
        raise FileExistsError(f"Output file {out_path} exists. Use --overwrite to overwrite.")

    filesize = in_path.stat().st_size
    with in_path.open('rb') as fin:
        # read fixed header
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("File format not recognized (invalid MAGIC).")
        salt = fin.read(SALT_SIZE)
        nonce = fin.read(NONCE_SIZE)
        # ciphertext_size = filesize - header - TAG
        header_len = len(MAGIC) + SALT_SIZE + NONCE_SIZE
        ct_size = filesize - header_len - TAG_SIZE
        if ct_size < 0:
            raise ValueError("File is too small or corrupted.")
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # read ciphertext in chunks (but ensure we don't consume the final tag)
        remaining = ct_size
        with out_path.open('wb') as fout:
            while remaining > 0:
                to_read = min(CHUNK_SIZE, remaining)
                chunk = fin.read(to_read)
                if not chunk:
                    raise EOFError("Unexpected EOF while reading ciphertext.")
                plain = cipher.decrypt(chunk)
                fout.write(plain)
                remaining -= len(chunk)

        # read tag and verify
        tag = fin.read(TAG_SIZE)
        if len(tag) != TAG_SIZE:
            # truncated / corrupted file
            raise ValueError("Tag missing or file corrupted.")
        try:
            cipher.verify(tag)
        except Exception as e:
            # Remove partial output file to avoid leaving corrupted plaintext
            try:
                out_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise ValueError("Authentication failed. Incorrect password or file has been tampered with.") from e


def process_directory_encrypt(indir: Path, outdir: Path, password: str, overwrite: bool=False) -> None:
    """
    Walk indir recursively and encrypt each file into outdir preserving structure.
    Encrypted filenames will have .enc appended.
    """
    for root, dirs, files in os.walk(indir):
        rel = Path(root).relative_to(indir)
        target_dir = outdir.joinpath(rel)
        target_dir.mkdir(parents=True, exist_ok=True)
        for fname in files:
            src = Path(root).joinpath(fname)
            dst = target_dir.joinpath(fname + '.enc')
            print(f"[+] Encrypt: {src} -> {dst}")
            try:
                encrypt_file(src, dst, password, overwrite=overwrite)
            except Exception as e:
                print(f"[!] Failed: {src}: {e}")


def process_directory_decrypt(indir: Path, outdir: Path, password: str, overwrite: bool=False) -> None:
    """
    Walk indir recursively and decrypt files with .enc suffix into outdir, removing .enc suffix.
    """
    for root, dirs, files in os.walk(indir):
        rel = Path(root).relative_to(indir)
        target_dir = outdir.joinpath(rel)
        target_dir.mkdir(parents=True, exist_ok=True)
        for fname in files:
            if not fname.endswith('.enc'):
                continue
            src = Path(root).joinpath(fname)
            out_name = fname[:-4] or fname + '.dec'
            dst = target_dir.joinpath(out_name)
            print(f"[+] Decrypt: {src} -> {dst}")
            try:
                decrypt_file(src, dst, password, overwrite=overwrite)
            except Exception as e:
                print(f"[!] Failed: {src}: {e}")

# === CLI ===
def cli():
    parser = argparse.ArgumentParser(description="CODTECH Advanced Encryption Tool (AES-256 GCM)")
    sub = parser.add_subparsers(dest='command', required=True)

    p_enc = sub.add_parser('encrypt', help='Encrypt a single file')
    p_enc.add_argument('--infile', '-i', required=True, help='Input file path')
    p_enc.add_argument('--outfile', '-o', required=False, help='Output file path (defaults to infile + .enc)')
    p_enc.add_argument('--password', '-p', required=False, help='Password (use with caution on shared shells)')
    p_enc.add_argument('--overwrite', action='store_true', help='Overwrite output if exists')

    p_dec = sub.add_parser('decrypt', help='Decrypt a single file')
    p_dec.add_argument('--infile', '-i', required=True, help='Input encrypted file path')
    p_dec.add_argument('--outfile', '-o', required=False, help='Output file path (defaults to infile with .enc removed)')
    p_dec.add_argument('--password', '-p', required=False, help='Password (use with caution on shared shells)')
    p_dec.add_argument('--overwrite', action='store_true', help='Overwrite output if exists')

    p_e_d = sub.add_parser('encrypt-dir', help='Encrypt all files in a directory (recursive)')
    p_e_d.add_argument('--indir', required=True, help='Input directory')
    p_e_d.add_argument('--outdir', required=True, help='Output directory root')
    p_e_d.add_argument('--password', '-p', required=False, help='Password (use with caution on shared shells)')
    p_e_d.add_argument('--overwrite', action='store_true', help='Overwrite outputs if exist')

    p_d_d = sub.add_parser('decrypt-dir', help='Decrypt all .enc files in a directory (recursive)')
    p_d_d.add_argument('--indir', required=True, help='Input directory')
    p_d_d.add_argument('--outdir', required=True, help='Output directory root')
    p_d_d.add_argument('--password', '-p', required=False, help='Password (use with caution on shared shells)')
    p_d_d.add_argument('--overwrite', action='store_true', help='Overwrite outputs if exist')

    if GUI_AVAILABLE:
        p_gui = sub.add_parser('gui', help='Run simple Tkinter GUI')

    args = parser.parse_args()

    try:
        if args.command == 'encrypt':
            infile = Path(args.infile)
            if not infile.exists():
                print("Input file does not exist.")
                return
            outfile = Path(args.outfile) if args.outfile else infile.with_name(infile.name + '.enc')
            password = args.password or getpass.getpass("Password: ")
            encrypt_file(infile, outfile, password, overwrite=args.overwrite)
            print(f"Encrypted -> {outfile}")

        elif args.command == 'decrypt':
            infile = Path(args.infile)
            if not infile.exists():
                print("Input file does not exist.")
                return
            if args.outfile:
                outfile = Path(args.outfile)
            else:
                # remove .enc suffix if present
                name = infile.name
                if name.endswith('.enc'):
                    outfile = infile.with_name(name[:-4])
                else:
                    outfile = infile.with_name(name + '.dec')
            password = args.password or getpass.getpass("Password: ")
            decrypt_file(infile, outfile, password, overwrite=args.overwrite)
            print(f"Decrypted -> {outfile}")

        elif args.command == 'encrypt-dir':
            indir = Path(args.indir)
            outdir = Path(args.outdir)
            if not indir.exists() or not indir.is_dir():
                print("Input directory invalid.")
                return
            outdir.mkdir(parents=True, exist_ok=True)
            password = args.password or getpass.getpass("Password for directory encryption: ")
            process_directory_encrypt(indir, outdir, password, overwrite=args.overwrite)
            print("Directory encryption complete.")

        elif args.command == 'decrypt-dir':
            indir = Path(args.indir)
            outdir = Path(args.outdir)
            if not indir.exists() or not indir.is_dir():
                print("Input directory invalid.")
                return
            outdir.mkdir(parents=True, exist_ok=True)
            password = args.password or getpass.getpass("Password for directory decryption: ")
            process_directory_decrypt(indir, outdir, password, overwrite=args.overwrite)
            print("Directory decryption complete.")

        elif args.command == 'gui':
            if not GUI_AVAILABLE:
                print("GUI components unavailable in this environment.")
                return
            run_gui()
    except Exception as e:
        print(f"[ERROR] {e}")
        # debug info:
        if os.environ.get('CT_DEBUG'):
            traceback.print_exc()

# === Simple Tkinter GUI ===
def run_gui():
    if not GUI_AVAILABLE:
        print("Tkinter not available on this system.")
        return

    root = tk.Tk()
    root.title("CODTECH Advanced Encryption Tool")
    root.geometry("700x480")

    frame = tk.Frame(root, padx=10, pady=10)
    frame.pack(fill='both', expand=True)

    infile_var = tk.StringVar()
    outfile_var = tk.StringVar()
    pass_var = tk.StringVar()
    mode_var = tk.StringVar(value='encrypt')

    def pick_file():
        p = filedialog.askopenfilename()
        if p:
            infile_var.set(p)
            outfile_var.set(p + ('.enc' if mode_var.get()=='encrypt' else '.dec'))

    def pick_outfile():
        p = filedialog.asksaveasfilename(defaultextension='')
        if p:
            outfile_var.set(p)

    def do_action():
        inf = infile_var.get().strip()
        outf = outfile_var.get().strip()
        pw = pass_var.get()
        if not inf or not outf or not pw:
            messagebox.showwarning("Missing", "Please choose file, outfile and enter password.")
            return
        try:
            if mode_var.get() == 'encrypt':
                encrypt_file(Path(inf), Path(outf), pw, overwrite=True)
                log(f"Encrypted {inf} -> {outf}")
                messagebox.showinfo("Done", f"Encrypted -> {outf}")
            else:
                decrypt_file(Path(inf), Path(outf), pw, overwrite=True)
                log(f"Decrypted {inf} -> {outf}")
                messagebox.showinfo("Done", f"Decrypted -> {outf}")
        except Exception as e:
            log(f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def log(msg: str):
        txt.configure(state='normal')
        txt.insert('end', msg + '\n')
        txt.see('end')
        txt.configure(state='disabled')

    top_row = tk.Frame(frame)
    top_row.pack(fill='x', pady=6)
    tk.Label(top_row, text="Mode:").pack(side='left')
    tk.Radiobutton(top_row, text='Encrypt', variable=mode_var, value='encrypt').pack(side='left')
    tk.Radiobutton(top_row, text='Decrypt', variable=mode_var, value='decrypt').pack(side='left')

    row1 = tk.Frame(frame)
    row1.pack(fill='x', pady=4)
    tk.Label(row1, text="Input File:").pack(side='left')
    tk.Entry(row1, textvariable=infile_var, width=60).pack(side='left', padx=4)
    tk.Button(row1, text="Browse", command=pick_file).pack(side='left')

    row2 = tk.Frame(frame)
    row2.pack(fill='x', pady=4)
    tk.Label(row2, text="Output File:").pack(side='left')
    tk.Entry(row2, textvariable=outfile_var, width=60).pack(side='left', padx=4)
    tk.Button(row2, text="Save as...", command=pick_outfile).pack(side='left')

    row3 = tk.Frame(frame)
    row3.pack(fill='x', pady=4)
    tk.Label(row3, text="Password:").pack(side='left')
    tk.Entry(row3, textvariable=pass_var, show='*', width=40).pack(side='left', padx=4)
    tk.Button(row3, text="Generate random", command=lambda: pass_var.set(base64.urlsafe_b64encode(get_random_bytes(24)).decode())).pack(side='left', padx=4)

    row4 = tk.Frame(frame)
    row4.pack(fill='x', pady=8)
    tk.Button(row4, text="Run", command=do_action, width=12).pack(side='left')
    tk.Button(row4, text="Clear Log", command=lambda: (txt.configure(state='normal'), txt.delete('1.0', 'end'), txt.configure(state='disabled'))).pack(side='left', padx=6)
    tk.Button(row4, text="Exit", command=root.destroy).pack(side='left', padx=6)

    txt = scrolledtext.ScrolledText(frame, height=15, state='disabled')
    txt.pack(fill='both', expand=True, pady=8)

    log("CODTECH Advanced Encryption Tool - GUI ready.")
    root.mainloop()


if __name__ == '__main__':
    cli()
