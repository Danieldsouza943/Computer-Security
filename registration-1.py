#Daniel Dsouza

import json
import os

# File to store user data
USER_DATA_FILE = 'users.json'

# Function to check if the file exists and load data
def load_users():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'r') as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return {}  # Handle empty or corrupted JSON file
    return {}

# Function to save users
def save_users(users):
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(users, file, indent=4)

# Function to register a new user
def register_user(users):
    full_name = input("Enter Full Name: ")
    email = input("Enter Email Address: ")
    
    # Ensuring email is not already registered
    if email in users:
        print("This email is already registered. Try logging in.")
        return

    # Ensuring password match
    while True:
        password = input("Enter Password: ")
        confirm_password = input("Re-enter Password: ")
        if password == confirm_password:
            print("Passwords Match.")
            break
        else:
            print("Passwords do not match. Try again.")
    
    users[email] = {'name': full_name, 'password': password}
    print("User Registered.")
    save_users(users)

# Function to log in an existing user
def login(users):
    email = input("Enter Email Address: ")
    password = input("Enter Password: ")
    
    # Validating email and password
    if email in users and users[email]['password'] == password:
        print(f"Username and Password verified. Welcome, {users[email]['name']}.")
    else:
        print("Invalid email or password.")

def main():
    users = load_users()
    
    # Check if any users are registered
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
