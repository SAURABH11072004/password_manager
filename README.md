# Password Manager

A simple and secure password manager that allows users to store, view, update, delete, and generate strong passwords. This application utilizes encryption to protect sensitive data and requires a master password for authentication.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- Techniques Used
- Code Explanation
- [Installation](#installation)
- [Usage](#usage)



## Features

- **Add a password**: Securely store a new password associated with an account.
- **View saved passwords**: Display all stored passwords.
- **Reveal a password**: Show the actual password for a specified account.
- **Update a password**: Change the password associated with an account.
- **Delete a password**: Remove a stored password.
- **Generate a strong password**: Create a random, secure password with varying complexity.

## Requirements

- Python 3.x
- Required libraries:
  - `cryptography`
  - `rich`

  ## Techniques Used

- **SHA-256**: 
  - The master password is hashed using the SHA-256 hashing algorithm for secure storage. This means that when you create or enter your master password, it is processed through SHA-256, resulting in a fixed-size hash that represents your password. 
  - **Why Use SHA-256?**
    - **Security**: SHA-256 is part of the SHA-2 family of cryptographic hash functions and is widely considered secure against collision and pre-image attacks.
    - **Irreversibility**: The hashing process is one-way, meaning that it is computationally infeasible to reverse the process to retrieve the original password from the hash.
    - **Data Integrity**: Hashes can be used to verify the integrity of the password without exposing the actual password, making it safe to store even if the storage medium is compromised.

- **Encryption**: 
  - Passwords are encrypted using the `Fernet` symmetric encryption method provided by the `cryptography` library. This ensures that stored passwords are not readable in plaintext, protecting sensitive information even if the storage file is accessed directly.

- **Rich Console Output**: 
  - The application utilizes the `rich` library to create a visually appealing and user-friendly console interface, enhancing user interaction and experience.

# Password Manager Code Explanation

This README provides a detailed explanation of the code structure and functionality for the Password Manager application.

## Code Structure

The Password Manager is implemented in a single Python file that contains several functions for handling passwords securely. Below is a breakdown of the key components:

1. **Imports**: 
   - The application imports necessary libraries:
     - `os`: For file and directory operations.
     - `json`: For storing and retrieving passwords in JSON format.
     - `getpass`: For securely handling user input without echoing it on the terminal.
     - `random` and `string`: For generating random passwords.
     - `hashlib`: For hashing the master password using SHA-256.
     - `Fernet` from `cryptography`: For encrypting and decrypting passwords.
     - `Console`, `Table`, and `box` from `rich`: For creating a visually appealing console interface.

2. **File and Key Management**:
   - **File Paths**: The variables `PASSWORD_FILE`, `KEY_FILE`, and `MASTER_PASSWORD_FILE` store the paths for the JSON file that contains passwords, the encryption key, and the master password file, respectively.
   - **Key Generation**: The function `load_or_generate_key` checks for the existence of the `KEY_FILE`. If it doesn't exist, it generates a new encryption key using `Fernet.generate_key()` and saves it. If the file does exist, it reads the key from the file.

3. **Encryption and Decryption**:
   - **Encrypting Passwords**: The function `encrypt_password` takes a password and an encryption key as input, uses `Fernet` to encrypt the password, and returns the encrypted password as a string.
   - **Decrypting Passwords**: The function `decrypt_password` takes an encrypted password and the encryption key, decrypts it using `Fernet`, and returns the original password.

4. **Hashing**:
   - **Hashing Master Passwords**: The function `hash_password` uses the SHA-256 hashing algorithm to hash the master password. This results in a fixed-size string that represents the original password securely.

5. **Master Password Setup and Authentication**:
   - **Setup or Verification**: The function `setup_or_verify_master_password` checks if a master password file exists. If not, it prompts the user to set a new master password and saves the hash. If the file exists, it calls the `authenticate` function to verify the password.
   - **Authentication**: The `authenticate` function reads the stored password hash and compares it with the hash of the user-entered password. If they match, authentication is successful.

6. **Password Management Functions**:
   - **Adding a Password**: The function `add_password` prompts the user for account details and encrypts the password before saving it to the JSON file.
   - **Viewing Passwords**: The function `view_passwords` retrieves and displays all stored passwords in a formatted table.
   - **Revealing a Password**: The function `reveal_password` takes an account name, authenticates the user, and if successful, decrypts and displays the corresponding password.
   - **Updating a Password**: The function `update_password` allows the user to change an existing password for a specified account.
   - **Deleting a Password**: The function `delete_password` removes a password entry associated with a specified account from storage.

7. **Password Generation**:
   - **Generating Strong Passwords**: The function `generate_password` creates a random password based on user-defined criteria such as length and complexity (low, medium, or high).

8. **Main Menu Loop**:
   - **User Interaction**: The `main` function contains a loop that displays a menu to the user, allowing them to choose actions like adding, viewing, updating, deleting passwords, or generating a new password. The user input determines which function is called.

## Conclusion

This code structure allows for a secure and user-friendly password management system that encrypts sensitive information and protects user data with a master password. The use of SHA-256 for password hashing and `Fernet` for encryption ensures that even if the data is accessed directly, it remains secure.

You can install the required libraries using pip:

```bash
pip install cryptography rich
pip install  rich.
