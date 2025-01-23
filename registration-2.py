#Daniel Dsouza

import json
import os
import hashlib
import binascii
from Crypto.Random import get_random_bytes
from getpass import getpass

# File to store user data
USER_DATA_FILE = 'users.json'

# Function to check if file exists and load data
def load_users():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'r') as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return {}
    return {}

# Function to save users
def save_users(users):
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(users, file, indent=4)

# Hash the password using SHA-256 and a random salt
def hash_password(password):
    salt = get_random_bytes(16)  # Generate a random salt
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash).decode('utf-8')
    salt = binascii.hexlify(salt).decode('utf-8')
    return f'{salt}:{pwdhash}'

# Verifying the stored password hash with the input password
def verify_password(stored_password, provided_password):
    salt, stored_hash = stored_password.split(':')
    salt = binascii.unhexlify(salt)
    pwdhash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash).decode('utf-8')
    return pwdhash == stored_hash

# Registration function
def register_user(users):
    full_name = input("Enter Full Name: ")
    email = input("Enter Email Address: ")
    
    if email in users:
        print("This email is already registered. Try logging in.")
        return
    
    # Use getpass to hide password input
    while True:
        password = getpass("Enter Password: ")
        confirm_password = getpass("Re-enter Password: ")
        if password == confirm_password:
            print("Passwords Match.")
            break
        else:
            print("Passwords do not match. Try again.")
    
    hashed_password = hash_password(password)  # Hash the password
    users[email] = {'name': full_name, 'password': hashed_password}
    print("User Registered with Secure Credentials.")
    save_users(users)

# Login function
def login(users):
    email = input("Enter Email Address: ")
    password = getpass("Enter Password: ")  # Use getpass to hide password input
    
    if email in users and verify_password(users[email]['password'], password):
        print(f"Username and Password verified. Welcome, {users[email]['name']}.")
    else:
        print("Invalid email or password.")

def main():
    users = load_users()
    
    if not users:
        print("No users are registered with this client.")
        choice = input("Do you want to register a new user (y/n)? ").lower()
        if choice == 'y':
            register_user(users)
    else:
        choice = input("Do you want to (l)ogin or (r)egister a new user? ").lower()
        if choice == 'r':
            register_user(users)
        elif choice == 'l':
            login(users)
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
