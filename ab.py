import os
import json
import getpass
import random
import string
import hashlib
from cryptography.fernet import Fernet
from rich.console import Console
from rich.table import Table
from rich import box
from rich import print as rprint

# Initialize console for rich output
console = Console()

# File and key paths
PASSWORD_FILE = "passwords.json"
KEY_FILE = "key.key"
MASTER_PASSWORD_FILE = "master_password.txt"

# Generate or load the encryption key
def load_or_generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key

# Encryption and decryption functions
def encrypt_password(password, key):
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

# Hashing function for the master password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to initialize or verify the master password
def setup_or_verify_master_password():
    if not os.path.exists(MASTER_PASSWORD_FILE):
        console.print("[bold yellow]No master password found. Please set a new master password.[/bold yellow]")
        master_password = getpass.getpass("Set a new master password: ")
        confirm_password = getpass.getpass("Confirm the new master password: ")
        if master_password == confirm_password:
            with open(MASTER_PASSWORD_FILE, "w") as file:
                file.write(hash_password(master_password))
            console.print("[bold green]Master password set successfully.[/bold green]")
        else:
            console.print("[bold red]Passwords do not match. Please try again.[/bold red]")
            setup_or_verify_master_password()
    else:
        return authenticate()

# Authentication function
def authenticate():
    if not os.path.exists(MASTER_PASSWORD_FILE):
        console.print("[bold red]Master password file is missing. Please set up a new master password.[/bold red]")
        setup_or_verify_master_password()
        return True
    
    with open(MASTER_PASSWORD_FILE, "r") as file:
        stored_password_hash = file.read().strip()
    input_password = getpass.getpass("Enter the master password: ")
    return hash_password(input_password) == stored_password_hash

# Add a new password
def add_password(key):
    if not authenticate():
        console.print("[bold red]Authentication failed.[/bold red]")
        return

    account_name = input("Enter account name: ")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    encrypted_password = encrypt_password(password, key)

    entry = {"account_name": account_name, "username": username, "password": encrypted_password}

    passwords = load_passwords()
    passwords.append(entry)
    save_passwords(passwords)
    console.print(f"[bold green]Password for {account_name} added successfully.[/bold green]")

# Load passwords from the JSON file
def load_passwords():
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r") as file:
            return json.load(file)
    return []

# Save passwords to the JSON file
def save_passwords(passwords):
    with open(PASSWORD_FILE, "w") as file:
        json.dump(passwords, file, indent=4)

# View all saved passwords
def view_passwords():
    if not authenticate():
        console.print("[bold red]Authentication failed.[/bold red]")
        return

    passwords = load_passwords()
    if not passwords:
        console.print("[bold yellow]No passwords saved.[/bold yellow]")
        return

    table = Table(title="Saved Passwords", box=box.SIMPLE)
    table.add_column("Account", style="cyan", no_wrap=True)
    table.add_column("Username", style="magenta", no_wrap=True)

    for entry in passwords:
        table.add_row(entry['account_name'], entry['username'])

    console.print(table)

# Reveal a password
def reveal_password(account_name, key):
    if not authenticate():
        console.print("[bold red]Authentication failed.[/bold red]")
        return

    passwords = load_passwords()
    for entry in passwords:
        if entry['account_name'] == account_name:
            decrypted_password = decrypt_password(entry['password'], key)
            console.print(f"[bold yellow]Password for {account_name}: {decrypted_password}[/bold yellow]")
            return
    console.print(f"[bold red]No password found for {account_name}.[/bold red]")

# Update an existing password
def update_password(account_name, key):
    if not authenticate():
        console.print("[bold red]Authentication failed.[/bold red]")
        return

    passwords = load_passwords()
    for entry in passwords:
        if entry['account_name'] == account_name:
            new_password = getpass.getpass("Enter the new password: ")
            entry['password'] = encrypt_password(new_password, key)
            save_passwords(passwords)
            console.print(f"[bold green]Password for {account_name} updated successfully.[/bold green]")
            return
    console.print(f"[bold red]No password found for {account_name}.[/bold red]")

# Delete a password
def delete_password(account_name):
    if not authenticate():
        console.print("[bold red]Authentication failed.[/bold red]")
        return

    passwords = load_passwords()
    passwords = [entry for entry in passwords if entry['account_name'] != account_name]
    save_passwords(passwords)
    console.print(f"[bold green]Password for {account_name} deleted successfully.[/bold green]")

# Generate a strong random password
def generate_password(length=16, complexity="high"):
    if complexity == "low":
        chars = string.ascii_letters
    elif complexity == "medium":
        chars = string.ascii_letters + string.digits
    else:
        chars = string.ascii_letters + string.digits + string.punctuation

    password = ''.join(random.choice(chars) for _ in range(length))
    console.print(f"[bold green]Generated password: {password}[/bold green]")

# Main menu
def main():
    key = load_or_generate_key()
    setup_or_verify_master_password()

    while True:
        console.print("\n[bold magenta]Password Manager[/bold magenta]")
        console.print("[bold yellow]1. Add a password[/bold yellow]")
        console.print("[bold yellow]2. View saved passwords[/bold yellow]")
        console.print("[bold yellow]3. Reveal a password[/bold yellow]")
        console.print("[bold yellow]4. Update a password[/bold yellow]")
        console.print("[bold yellow]5. Delete a password[/bold yellow]")
        console.print("[bold yellow]6. Generate a strong password[/bold yellow]")
        console.print("[bold yellow]0. Exit[/bold yellow]")

  
  
        choice = input("Enter your choice: ")

        if choice == "1":
            add_password(key)
        elif choice == "2":
            view_passwords()
        elif choice == "3":
            account_name = input("Enter the account name: ")
            reveal_password(account_name, key)
        elif choice == "4":
            account_name = input("Enter the account name: ")
            update_password(account_name, key)
        elif choice == "5":
            account_name = input("Enter the account name: ")
            delete_password(account_name)
        elif choice == "6":
            length = int(input("Enter the password length (default 16): ") or 16)
            complexity = input("Enter the complexity (low, medium, high): ").lower() or "high"
            generate_password(length, complexity)
        elif choice == "0":
            console.print("[bold red]Exiting the Password Manager.[/bold red]")
            break
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")

if __name__ == "__main__":
    main()
