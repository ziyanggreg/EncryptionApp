"""
Greg's Encryption Application
This is a simple file encryption application that allows the user to select a file to encrypt or decrypt, and uses the AES, ARC4, or DES3 encryption algorithms with a 256-bit key.
The application uses the following modules:
tkinter: for the graphical user interface
filedialog: for selecting the file to encrypt/decrypt
messagebox: for displaying error messages and success messages
ScrolledText: for displaying instructions and about information in a separate window
Crypto.Cipher: for the encryption/decryption algorithms (AES, ARC4, and DES3)
Crypto.Hash: for hashing the encryption key
os: for getting file size and generating random initialization vectors
Author: Greg Zhang
Author email: ziyangz@csu.fullerton.edu
Date created: 2022-04-25
Last modified: 2022-05-01
"""

import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from Crypto.Cipher import AES, ARC4, DES3
from Crypto.Hash import SHA256
import os

root = tk.Tk()
root.title("Greg's Encryption Application")
root.geometry("450x550")

# ScrolledText widget to display the selected files
filename_text = ScrolledText(root, wrap=tk.WORD, width=50, height=5, font=("Arial", 12))
filename_text.pack(pady=10)

# Label for encryption key entry
key_label = tk.Label(root, text="Enter encryption key:", font=("Arial", 12))
key_label.pack(pady=10)

# Entry box to enter the encryption key
key_entry = tk.Entry(root, font=("Arial", 12))
key_entry.pack()

# Label for encryption algorithm selection
algorithm_label = tk.Label(root, text="Select encryption algorithm:", font=("Arial", 12))
algorithm_label.pack(pady=10)

# Drop-down menu to select encryption algorithm
algorithm_var = tk.StringVar(root)
algorithm_var.set("AES") # default value
algorithm_menu = tk.OptionMenu(root, algorithm_var, "AES", "ARC4", "DES3")
algorithm_menu.pack()

# Global variables to hold the encryption key and algorithm
key = ""
algorithm = ""

def select_file():
    global filenames
    filenames = filedialog.askopenfilenames()
    if filenames:
        filename_text.delete("1.0", tk.END) # clear the text area
        for filename in filenames:
            filename_text.insert(tk.END, filename + "\n")
    else:
        filename_text.delete("1.0", tk.END) # clear the text area
        filename_text.insert(tk.END, "No file selected")

def encrypt_file():
    try:
        global key, algorithm
        key = key_entry.get()
        algorithm = algorithm_var.get()

        if not key:
            raise ValueError("Encryption key cannot be empty or null")

        key_bytes = bytes(key, 'utf-8')
        key_pad = key_bytes.ljust(24, b' ')
        key_hash = SHA256.new(key_pad).digest()[:24]

        for filename in filenames:
            encrypt_file_with_key(key_hash, filename, algorithm)

        messagebox.showinfo("Encryption successful", "Files encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_file():
    try:
        global key, algorithm
        key = key_entry.get()
        algorithm = algorithm_var.get()

        if not key:
            raise ValueError("Decryption key cannot be empty or null")

        key_bytes = bytes(key, 'utf-8')
        key_pad = key_bytes.ljust(24, b' ')
        key_hash = SHA256.new(key_pad).digest()[:24]

        for filename in filenames:
            decrypt_file_with_key(key_hash, filename, algorithm)

        messagebox.showinfo("Decryption successful", "Files decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def show_instructions():
    instructions = """INSTRUCTIONS:
1. Click the 'Select target file' button to choose a file to encrypt or decrypt.

2. Enter a key in the 'Enter encryption key' field.

3. Select an encryption algorithm from the drop-down menu. The application supports three encryption algorithms: AES, ARC4, and DES3.

4. Click the 'Encrypt file' or 'Decrypt file' button to encrypt or decrypt the selected file.

NOTE: Make sure to remember the encryption key and algorithm as they will be required to decrypt the file(s) later."""


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

Greg's Encryption Application is a simple tool that allows you to encrypt and decrypt files using industry-standard encryption algorithms.

This application is designed to be user-friendly and easy to use. Simply select one or more files, enter an encryption key, and choose an encryption algorithm to perform the desired operation. The application currently supports three encryption algorithms: AES, ARC4, and DES3.

AES (Advanced Encryption Standard) is a symmetric block cipher encryption algorithm that was standardized by NIST (National Institute of Standards and Technology) in 2001. It is widely used in modern encryption applications due to its strong encryption and speed.

ARC4 is a symmetric stream cipher encryption algorithm that was designed by Ron Rivest in 1987. It is widely used in protocols such as SSL/TLS and WEP due to its simplicity and speed.

DES3, also known as Triple DES, is an improvement on the original DES (Data Encryption Standard) algorithm that uses three 56-bit keys to provide a higher level of security. However, it is still not recommended for use in new applications due to its relatively slow speed and susceptibility to attacks.

SHA256 is used in this application to generate a secure key from the user-entered encryption key.
When the user enters an encryption key, it is first padded to a length of 24 bytes using the 'ljust()' method. The resulting padded key is then passed to the SHA256 hash function, which generates a 256-bit hash value that is used as the actual encryption key.
This process of hashing the user-entered key ensures that the key is secure and cannot be easily guessed or cracked by attackers.

Please email any comments or questions."""

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
select_file_button = tk.Button(root, text="Select target file(s)", command=select_file, font=("Arial", 12))
select_file_button.pack(pady=10)

# Button to encrypt the selected file
encrypt_button = tk.Button(root, text="Encrypt file", command=encrypt_file, font=("Arial", 12), bg="red", padx=20, pady=10)
encrypt_button.pack(pady=10)

# Button to decrypt the selected file
decrypt_button = tk.Button(root, text="Decrypt file", command=decrypt_file, font=("Arial", 12), bg="green", padx=20, pady=10)
decrypt_button.pack(pady=10)

# Button to show instructions
instructions_button = tk.Button(root, text="Instructions", command=show_instructions)
instructions_button.pack(side="left", anchor="sw", padx=10, pady=10)

# Button to show about information
about_button = tk.Button(root, text="About", command=show_about)
about_button.pack(side="right", anchor="se", padx=10, pady=10)

# Move the buttons up by setting pady to 5
encrypt_button.pack(pady=(20,5))
decrypt_button.pack(pady=(0,5))
instructions_button.pack(side="left", anchor="sw", pady=(20,5), padx=10)  # move instructions button up
about_button.pack(side="right", anchor="se", pady=(20,5), padx=10)  # move about button up

def encrypt_file_with_key(key, filename, algorithm):
    chunk_size = 64 * 1024
    output_file = filename + ".enc"
    filesize = str(os.path.getsize(filename)).zfill(16)
    iv = os.urandom(16)

    if algorithm == "AES":
        encryptor = AES.new(key, AES.MODE_CBC, iv)
    elif algorithm == "ARC4":
        encryptor = ARC4.new(key)
    elif algorithm == "DES3":
    # For DES3, the IV must be 8 bytes long
        iv = os.urandom(8)
        encryptor = DES3.new(key, DES3.MODE_CBC, iv)

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

def decrypt_file_with_key(key, filename, algorithm):
    chunk_size = 64 * 1024
    output_file = filename[:-4]

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        iv = infile.read(8) if algorithm == "DES3" else infile.read(16)

        if algorithm == "AES":
            decryptor = AES.new(key, AES.MODE_CBC, iv)
        elif algorithm == "ARC4":
            decryptor = ARC4.new(key)
        elif algorithm == "DES3":
            decryptor = DES3.new(key, DES3.MODE_CBC, iv)

        with open(output_file, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(filesize)

root.mainloop()
