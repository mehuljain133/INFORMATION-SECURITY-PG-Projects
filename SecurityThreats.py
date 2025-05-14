# Unit-II Security Threats: Program threats, worms, viruses, Trojan horse, trap door, stack and buffer overflow; system threats- intruders; communication threats- tapping and piracy.

import random
import string
import time

# Simulating different types of security threats

class SecurityThreats:
    def __init__(self):
        self.system_state = "Secure"
        self.user_db = {"admin": "adminpassword"}
        self.session_data = {}
    
    # Program Threats: Worms, Viruses, Trojan Horses, etc.
    def worm(self, system):
        print("Worm is attempting to spread across the system...")
        system['spread'] = True  # Simulating worm spreading
        print("Worm has spread across the system.")
    
    def virus(self, file):
        print(f"Virus is attempting to corrupt the file: {file}")
        file['corrupted'] = True  # Simulate file corruption
        print(f"File {file['name']} is now corrupted.")
    
    def trojan_horse(self):
        print("Trojan Horse is attempting to access sensitive data...")
        # Simulate the trojan horse using social engineering to access sensitive data
        trojan_access = True
        if trojan_access:
            print("Trojan Horse successfully accessed sensitive data.")
            sensitive_data = {"passwords": "supersecret"}
            return sensitive_data
        else:
            print("Trojan Horse failed to gain access.")
            return None
    
    def trap_door(self):
        print("Trap Door has been inserted into the system.")
        # A trap door allows an intruder to bypass normal authentication
        # This is a simulated scenario for security education
        trapdoor_access = True
        if trapdoor_access:
            print("Trap Door used to bypass normal authentication.")
            return True
        else:
            print("Trap Door access denied.")
            return False
    
    def buffer_overflow(self):
        print("Attempting buffer overflow attack...")
        # A buffer overflow attempt might overwrite memory and lead to security vulnerabilities
        input_data = "A" * 1000  # Simulate an oversized input that could cause buffer overflow
        if len(input_data) > 512:  # Simulated buffer size
            print("Buffer overflow detected! Vulnerability exploited.")
            return True
        else:
            print("Buffer overflow attempt failed.")
            return False
    
    # System Threats: Intruders
    def intruder_attack(self):
        print("Intruder is attempting unauthorized access...")
        intruder_success = random.choice([True, False])
        if intruder_success:
            print("Intruder successfully gained unauthorized access!")
            self.system_state = "Compromised"
        else:
            print("Intruder failed to gain access.")
    
    # Communication Threats: Tapping, Piracy
    def tapping_attack(self, message):
        print(f"Communication Tapping: Attempting to intercept the message: {message}")
        intercepted_message = message
        print(f"Intercepted message: {intercepted_message}")
        return intercepted_message
    
    def piracy_attack(self, software):
        print(f"Software Piracy: Attempting to copy or distribute pirated software: {software}")
        piracy_success = random.choice([True, False])
        if piracy_success:
            print(f"Piracy attempt successful! {software} is now pirated.")
        else:
            print("Piracy attempt failed.")

# Demonstrating various threats
threats_system = SecurityThreats()

# 1. Program Threats
print("\n=== Program Threats ===")
file = {'name': 'important_file.txt', 'corrupted': False}
threats_system.virus(file)

# Simulate a Trojan Horse
sensitive_data = threats_system.trojan_horse()
if sensitive_data:
    print("Sensitive data accessed:", sensitive_data)

# Trap Door
trapdoor_access = threats_system.trap_door()
if trapdoor_access:
    print("Trap Door Access Granted.")
else:
    print("No Trap Door Access.")

# Buffer Overflow
threats_system.buffer_overflow()

# 2. System Threats: Intruders
print("\n=== System Threats ===")
threats_system.intruder_attack()

# 3. Communication Threats
print("\n=== Communication Threats ===")
message = "This is a secret message."
intercepted_message = threats_system.tapping_attack(message)

# Software Piracy
software = "Windows 10"
threats_system.piracy_attack(software)

# Print final system state
print("\n=== Final System State ===")
print(f"System State: {threats_system.system_state}")
