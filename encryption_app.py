import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os

root = tk.Tk()
root.title("Encryption Application")
root.geometry("400x400")

# Label to display the file name
filename_label = tk.Label(root, text="No file selected")
filename_label.pack()

# Entry box to enter the encryption key
key_entry = tk.Entry(root)
key_entry.pack()

# Global variable to hold the encryption key
key = ""

def select_file():
    global filename
    filename = filedialog.askopenfilename()
    filename_label.config(text=filename)

def encrypt_file():
    try:
        key = key_entry.get()
        if not key:
            raise ValueError("Encryption key cannot be empty or null")
        key_bytes = bytes(key, 'utf-8')
        key_hash = SHA256.new(key_bytes).digest()[:32]
        encrypt_file_with_key(key_hash, filename)
        messagebox.showinfo("Encryption successful", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_file():
    try:
        key = key_entry.get()
        if not key:
            raise ValueError("Decryption key cannot be empty or null")
        key_bytes = bytes(key, 'utf-8')
        key_hash = SHA256.new(key_bytes).digest()[:32]
        decrypt_file_with_key(key_hash, filename)
        messagebox.showinfo("Decryption successful", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Button to select the file to encrypt
select_file_button = tk.Button(root, text="Select file", command=select_file)
select_file_button.pack()

# Button to encrypt the selected file
encrypt_button = tk.Button(root, text="Encrypt file", command=encrypt_file)
encrypt_button.pack()

# Button to decrypt the selected file
decrypt_button = tk.Button(root, text="Decrypt file", command=decrypt_file)
decrypt_button.pack()

def encrypt_file_with_key(key, filename):
    chunk_size = 64 * 1024
    output_file = filename + ".enc"
    filesize = str(os.path.getsize(filename)).zfill(16)
    iv = os.urandom(16)

    encryptor = AES.new(key, AES.MODE_CBC, iv)

    with open(filename, 'rb') as infile:
        with open(output_file, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunk_size)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))

def decrypt_file_with_key(key, filename):
    chunk_size = 64 * 1024
    output_file = filename[:-4]

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        iv = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(output_file, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(filesize)

root.mainloop()
