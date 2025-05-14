# Unit-I Overview of Security: Protection versus security; aspects of security– confidentiality, data integrity, availability, privacy; user authentication, access controls, Orange Book Standard.

import hashlib
import random
import string
import os
import time

# Class to demonstrate basic security concepts
class InformationSecurity:
    def __init__(self):
        self.user_db = {}  # Simulate a user database (username: password_hash)
        self.access_control_list = {}  # Simulate an ACL (username: access_level)
    
    # 1. **Confidentiality** - Encrypt data before storing or transmitting it.
    def encrypt_data(self, data):
        # Using hashlib for simple encryption (in reality, you'd use libraries like pycryptodome)
        hash_object = hashlib.sha256(data.encode())
        encrypted_data = hash_object.hexdigest()
        return encrypted_data

    # 2. **Data Integrity** - Ensure data hasn't been tampered with.
    def verify_integrity(self, data, hash_value):
        encrypted_data = self.encrypt_data(data)
        if encrypted_data == hash_value:
            print("Data Integrity Check Passed")
        else:
            print("Data Integrity Check Failed")
    
    # 3. **Availability** - Simulate system availability through uptime.
    def simulate_system_uptime(self):
        # Simulate system uptime with a delay (e.g., the system is available for use)
        uptime = random.randint(1, 10)  # Random uptime in hours
        print(f"System is up for {uptime} hours")
        time.sleep(uptime)  # Simulating system downtime
        print("System is available again.")

    # 4. **Privacy** - Basic User Authentication and Session Management
    def register_user(self, username, password):
        password_hash = self.encrypt_data(password)
        self.user_db[username] = password_hash
        print(f"User {username} registered successfully.")
    
    def authenticate_user(self, username, password):
        if username in self.user_db:
            if self.user_db[username] == self.encrypt_data(password):
                print(f"User {username} authenticated successfully.")
                return True
            else:
                print("Authentication failed: Incorrect password.")
                return False
        else:
            print("Authentication failed: User does not exist.")
            return False
    
    # 5. **Access Controls** - Set permissions for users
    def set_access_control(self, username, level):
        self.access_control_list[username] = level
        print(f"Access control set for {username} with level {level}.")
    
    def check_access(self, username):
        if username in self.access_control_list:
            print(f"User {username} has access level: {self.access_control_list[username]}")
        else:
            print(f"No access control for {username}.")
    
    # Orange Book Standard Reference: This is more of a framework, not directly implementable
    def orange_book_standard(self):
        print("Orange Book Standard - Focuses on evaluation criteria for secure systems.")
        print("It defines several security classifications from D (Minimal Protection) to A1 (Verified Protection).")
        print("We are implementing basic security features like confidentiality, integrity, availability, and access control in this system.")

# Example usage
security_system = InformationSecurity()

# 1. Register users
security_system.register_user('Alice', 'password123')
security_system.register_user('Bob', 'securepassword')

# 2. User Authentication
security_system.authenticate_user('Alice', 'password123')

# 3. Set Access Control
security_system.set_access_control('Alice', 'admin')
security_system.set_access_control('Bob', 'user')

# 4. Check Access
security_system.check_access('Alice')
security_system.check_access('Bob')

# 5. Data Integrity Example
data = "Sensitive information"
hash_value = security_system.encrypt_data(data)
security_system.verify_integrity(data, hash_value)

# 6. Simulate System Availability
security_system.simulate_system_uptime()

# 7. Orange Book Standard Reference
security_system.orange_book_standard()
