# Password Manager

A simple and secure password manager that allows users to store, view, update, delete, and generate strong passwords. This application utilizes encryption to protect sensitive data and requires a master password for authentication.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Code Explanation](#code-explanation)


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


You can install the required libraries using pip:

```bash
pip install cryptography rich

pip install  rich
