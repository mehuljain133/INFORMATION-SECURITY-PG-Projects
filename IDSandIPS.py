# Unit-VI Intrusion detection and prevention.

import random
import time
import string
from collections import Counter

# Helper function to generate random "network traffic" data
def generate_random_network_data(length=100):
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))

# --- Signature-Based Intrusion Detection ---
signature_patterns = ['malware', 'attack', 'bypass', 'exploit', 'hacker']

def signature_detection(traffic_data):
    """
    Signature-based detection: Check for predefined attack patterns in the network traffic.
    """
    for pattern in signature_patterns:
        if pattern in traffic_data.lower():
            print(f"ALERT: Signature-based Intrusion Detected! Pattern '{pattern}' found.")
            return True
    return False

# --- Anomaly-Based Intrusion Detection ---
def anomaly_detection(traffic_data, normal_data_frequency):
    """
    Anomaly-based detection: Check if the frequency of certain patterns deviates from normal traffic.
    """
    # Calculate the frequency of each character
    traffic_freq = Counter(traffic_data)
    
    # Compare traffic frequencies to normal baseline frequencies
    for char, count in traffic_freq.items():
        if count > normal_data_frequency.get(char, 0) * 2:  # If anomaly is detected (frequency is too high)
            print(f"ALERT: Anomaly Detected! Character '{char}' appears too often in traffic.")
            return True
    return False

# --- Intrusion Prevention System (IPS) ---
def prevention_system(detected_intrusion, prevention_action="block"):
    """
    Prevention system that reacts to detected intrusions.
    """
    if detected_intrusion:
        if prevention_action == "block":
            print("BLOCK: Intrusion blocked by the prevention system.")
        elif prevention_action == "alert":
            print("ALERT: Intrusion detected, alerting administrator.")
        else:
            print("PREVENTION SYSTEM: Unknown action.")
    else:
        print("No intrusion detected. System is secure.")

# --- Simulated Network Traffic Monitoring ---
def monitor_network_traffic(duration=10, normal_data_frequency=None):
    """
    Monitor network traffic for a specific duration, detect and prevent intrusions.
    """
    print("Starting network traffic monitoring...\n")

    if normal_data_frequency is None:
        normal_data_frequency = Counter(generate_random_network_data(100))  # Simulate normal data frequency

    start_time = time.time()
    while time.time() - start_time < duration:
        # Simulate traffic
        network_data = generate_random_network_data(100)

        print(f"\n[Network Traffic] Data: {network_data}")

        # Signature-based detection
        detected_intrusion_signature = signature_detection(network_data)

        # Anomaly-based detection
        detected_intrusion_anomaly = anomaly_detection(network_data, normal_data_frequency)

        # Combined intrusion detection
        detected_intrusion = detected_intrusion_signature or detected_intrusion_anomaly

        # Intrusion Prevention (Block or Alert)
        prevention_system(detected_intrusion, prevention_action="block" if detected_intrusion else "alert")

        # Simulate normal traffic update for anomaly detection (this would normally update over time)
        normal_data_frequency.update(network_data)

        # Wait for next cycle
        time.sleep(1)

# --- Example Usage ---
if __name__ == "__main__":
    monitor_network_traffic(duration=10)
