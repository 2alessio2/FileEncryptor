import tkinter as tk
from tkinter import filedialog, messagebox
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Function to generate a key derived from a password and a salt
def generate_key(password: str, salt: str):
    salt = salt.encode()  # Convert salt to bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Function to encrypt a file
def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    password = password_entry.get()
    salt = salt_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password")
        return
    if not salt:
        messagebox.showerror("Error", "Please enter a salt")
        return
    
    key = generate_key(password, salt)
    cipher = Fernet(key)
    
    with open(file_path, "rb") as file:
        file_data = file.read()
    encrypted_data = cipher.encrypt(file_data)
    
    encrypted_path = file_path + ".enc"
    with open(encrypted_path, "wb") as file:
        file.write(encrypted_data)
    
    messagebox.showinfo("Success", f"File encrypted: {encrypted_path}")

# Function to decrypt a file
def decrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    password = password_entry.get()
    salt = salt_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password")
        return
    if not salt:
        messagebox.showerror("Error", "Please enter a salt")
        return
    
    key = generate_key(password, salt)
    cipher = Fernet(key)
    
    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = cipher.decrypt(encrypted_data)
    
        decrypted_path = file_path.replace(".enc", "_decrypted")
        with open(decrypted_path, "wb") as file:
            file.write(decrypted_data)
    
        messagebox.showinfo("Success", f"File decrypted: {decrypted_path}")
    except Exception as e:
        messagebox.showerror("Error", "Incorrect password, salt, or corrupted file")

# Create the GUI
root = tk.Tk()
root.title("File Encryptor")
root.geometry("400x200")

frame = tk.Frame(root)
frame.pack(pady=20)

tk.Label(frame, text="Enter password:").pack()
password_entry = tk.Entry(frame, show="*", width=30)
password_entry.pack()

tk.Label(frame, text="Enter salt (custom):").pack()
salt_entry = tk.Entry(frame, width=30)
salt_entry.pack()

tk.Button(frame, text="Encrypt File", command=encrypt_file).pack(pady=5)
tk.Button(frame, text="Decrypt File", command=decrypt_file).pack(pady=5)

root.mainloop()
