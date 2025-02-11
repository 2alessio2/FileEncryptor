
# File Encryptor

## Description

This program allows users to encrypt and decrypt files using a custom password. It uses the `cryptography` library for secure encryption with **AES-128** (Fernet) and a key derived from the password using **PBKDF2-HMAC-SHA256**.

## Features

- **File encryption** with a custom password
- **File decryption** if the correct password and salt are provided
- **Simple GUI** built with `tkinter`

## Requirements

Make sure you have the `cryptography` library installed:

```bash
pip install cryptography
```

## Usage

### 1️⃣ Running the Program

Run the Python script to open the graphical user interface:

```bash
python encryptor.py
```

### 2️⃣ Encrypting a File

1. Enter a password in the text field.
2. Enter a custom salt (a string) in the corresponding text field.
3. Click the "Encrypt File" button.
4. Choose a file to encrypt.
5. A new file will be created with the `.enc` extension.

### 3️⃣ Decrypting a File

1. Enter the same password and salt used for encryption.
2. Click the "Decrypt File" button.
3. Choose an `.enc` file to decrypt.
4. The file will be decrypted and saved with `_decrypted` appended to the filename.

## Security

- Uses **PBKDF2** to derive a secure key from the password.
- Protects against brute-force attacks with **100,000 iterations**.
- Encrypts the file with **AES-128** (Fernet) for confidentiality.

⚠️ **Note:** The program uses a fixed `salt` for key derivation. For better security, it would be preferable to generate a random salt for each file and store it with the encrypted file.

## Future Improvements

- **Dynamic salt management** to improve security.
- **Enhanced protection against brute-force attacks**.
- **File authentication using HMAC** for better data integrity.

## License

This project is licensed under the MIT License.
