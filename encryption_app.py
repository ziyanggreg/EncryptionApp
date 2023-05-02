"""
Greg's Encryption Application

This is a simple file encryption application that uses the AES encryption algorithm with a 256-bit key. The user selects a file to encrypt or decrypt, enters an encryption key, and then clicks the appropriate button to perform the operation.

The application uses the following modules:
tkinter: for the graphical user interface
filedialog: for selecting the file to encrypt/decrypt
messagebox: for displaying error messages and success messages
ScrolledText: for displaying instructions in a separate window
Crypto.Cipher: for the AES encryption/decryption
Crypto.Hash: for hashing the encryption key
os: for getting file size and generating random initialization vectors

Instructions:
Click the 'Select target file' button to choose a file to encrypt or decrypt.
Enter a key in the 'Enter encryption key' field.
Click the 'Encrypt file' or 'Decrypt file' button to encrypt or decrypt the selected file.
Note: Make sure to remember the encryption key as it will be required to decrypt the file later.

Author: Greg Zhang
Author email: ziyangz@csu.fullerton.edu
Date created: 2022-04-25
Last modified: 2022-05-01
"""

import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os

root = tk.Tk()
root.title("Greg's Encryption Application")
root.geometry("400x400")

# Label to display the file name
filename_label = tk.Label(root, text="No file selected", font=("Arial", 12, "bold"))
filename_label.pack(pady=10)

# Label for encryption key entry
key_label = tk.Label(root, text="Enter encryption key:", font=("Arial", 12))
key_label.pack(pady=10)

# Entry box to enter the encryption key
key_entry = tk.Entry(root, font=("Arial", 12))
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

def show_instructions():
    instructions = """INSTRUCTIONS:

1. Click the 'Select target file' button to choose a file to encrypt or decrypt.
2. Enter a key in the 'Enter encryption key' field.
3. Click the 'Encrypt file' or 'Decrypt file' button to encrypt or decrypt the selected file.

NOTE: Make sure to remember the encryption key as it will be required to decrypt the file later."""

    # Window to display the instructions
    window = tk.Toplevel()
    window.title("Instructions")
    window.geometry("400x400")

    # ScrolledText widget to display the instructions
    text_box = ScrolledText(window, wrap=tk.WORD, width=50, height=20, font=("Arial", 12))
    text_box.pack(expand=True, fill="both")
    text_box.insert(tk.END, instructions)
    text_box.configure(state="disabled") # disable editing

def show_about():
    about_text = """Greg's Encryption Application

Version 0.1

Author: Greg Zhang
Author Email: ziyangz@csu.fullerton.edu

This application allows you to encrypt and decrypt files using AES encryption. Simply select a file, enter an encryption key, and click the 'Encrypt file' or 'Decrypt file' button to perform the operation.

Enjoy!"""

    # create a new window to display the about information
    window = tk.Toplevel()
    window.title("About")
    window.geometry("400x400")

    # create a ScrolledText widget to display the information
    text_box = ScrolledText(window, wrap=tk.WORD, width=50, height=20, font=("Arial", 12))
    text_box.pack(expand=True, fill="both")
    text_box.insert(tk.END, about_text)
    text_box.configure(state="disabled") # disable editing

# Button to select the file to encrypt
select_file_button = tk.Button(root, text="Select target file", command=select_file, font=("Arial", 12))
select_file_button.pack(pady=20)

# Button to encrypt the selected file
encrypt_button = tk.Button(root, text="Encrypt file", command=encrypt_file, font=("Arial", 12), bg="red", padx=20, pady=10)
encrypt_button.pack(pady=20)

# Button to decrypt the selected file
decrypt_button = tk.Button(root, text="Decrypt file", command=decrypt_file, font=("Arial", 12), bg="green", padx=20, pady=10)
decrypt_button.pack(pady=20)

# Button to show instructions
instructions_button = tk.Button(root, text="Instructions", command=show_instructions)
instructions_button.pack(side="left", anchor="sw", padx=10, pady=10)

# Button to show about information
about_button = tk.Button(root, text="About", command=show_about)
about_button.pack(side="right", anchor="se", padx=10, pady=10)

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
