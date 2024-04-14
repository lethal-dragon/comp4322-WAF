# from scapy.all import *
# import re
# import time
#
#
# # Dictionary to hold packet count per IP
# packet_counts = {}
# # Time to reset counts, in seconds
# RESET_INTERVAL = 30
# # Maximum allowed packets per IP within the reset interval
# RATE_LIMIT = 10
# # Time when we last reset the counts
# last_reset_time = time.time()
#
# BLACKLISTED_IPS = []
#
# def is_blacklisted_ip(packet):
#     """
#     Check if the source IP is blacklisted.
#     """
#     src_ip = packet[IP].src
#     if src_ip in BLACKLISTED_IPS:
#         print(f"Blocking blacklisted IP: {src_ip}")
#         return True
#     return False
#
# def rate_limit(packet):
#     """
#     Implement rate limiting for incoming packets.
#     """
#     global last_reset_time
#     # Check for the current time and reset if needed
#     current_time = time.time()
#     if current_time - last_reset_time > RESET_INTERVAL:
#         packet_counts.clear()
#         last_reset_time = current_time
#
#     # Get source IP address
#     src_ip = packet[IP].src
#     if src_ip in packet_counts:
#         packet_counts[src_ip] += 1
#     else:
#         packet_counts[src_ip] = 1
#
#     # Check if the source IP has exceeded the rate limit
#     if packet_counts[src_ip] > RATE_LIMIT:
#         print(f"Rate limit exceeded for {src_ip}. Packet blocked.")
#         return False  # Block the packet
#
#     return True  # Allow the packet
#
#
# def firewall_rules(packet):
#     """
#     Define firewall rules.
#     This example blocks outgoing HTTP traffic (port 80) and SQL injection attempts.
#     """
#
#
#     # Check if the packet is a TCP packet and destined for port 80
#     if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
#         # Check if the packet has a Raw layer (this is where HTTP data is)
#         http_payload = packet[Raw].load.decode('utf-8', errors='ignore')
#         # Check if the payload is an HTTP GET request with a SQL injection attempt
#         if http_payload.startswith('GET') and is_potential_sql_injection(http_payload):
#             print("Blocking SQL injection attempt.")
#             return False  # Indicate that this packet should be blocked
#         if http_payload.startswith('GET') and is_potential_file_inclusion(http_payload):
#             print("Blocking file inclusion attempt.")
#             return False
#         if http_payload.startswith('GET') and is_blacklisted_ip(http_payload):
#             print("Blocking Blacklisted IP.")
#             return False
#
#     # New: Basic analysis of POST requests
#     if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
#         http_payload = packet[Raw].load.decode('utf-8', errors='ignore')  # Decode with error handling
#         if http_payload.startswith('POST'):
#             print("Detected HTTP POST request.")
#             # This is where you'd look for CSRF tokens in a real scenario
#             # For simulation, you might log a warning if expected token patterns are missing:
#             if "csrf_token" not in http_payload:
#                 print("Warning: Possible missing CSRF protection in POST request.")
#                 return False  # Indicate that this packet should be blocked
#
#     return True  # Indicate that this packet passes the firewall
#
#
# def is_potential_sql_injection(payload):
#     """
#     Enhances detection for specific SQL injection examples.
#     """
#     patterns = [
#         r"1=1",  # Tautology, checking specifically for "1=1"
#         r"--",  # Commenting out the rest of the SQL command
#         r"(?i)\bUNION\b.*\bSELECT\b",  # UNION SELECT to retrieve data from other tables
#         # Additional patterns for common SQL injection techniques:
#         r"(?i)\bINSERT\b.+?\bINTO\b.+?\bVALUES\b",  # Detecting attempts to insert data
#         r"(%27)|(')",  # Detecting single quote characters, common in SQLi
#         # Detect administrator'-- pattern specifically for subverting logic:
#         r"(?i)administrator'--",
#     ]
#     for pattern in patterns:
#         if re.search(pattern, payload):
#             src_ip = packet[IP].src
#             BLACKLISTED_IPS.append(src_ip)
#             return True
#     return False
#
# def is_potential_file_inclusion(payload):
#     """
#     Enhances detection for specific file inclusion examples.
#     """
#     patterns = [
#         r"etc/passwd",  # Accessing the passwd file
#         r"../../etc/passwd",  # Traversal to access passwd file
#         r"php://input",  # PHP input wrapper
#         r"php://filter",  # PHP filter wrapper
#         r"expect://ls",  # Using expect to execute commands
#         r"file:///etc/passwd",  # File inclusion with file://
#         r"auto_prepend_file",  # PHP auto_prepend_file
#     ]
#     for pattern in patterns:
#         if re.search(pattern, payload):
#             src_ip = packet[IP].src
#             BLACKLISTED_IPS.append(src_ip)
#             return True
#     return False
#
#
# def packet_sniffer(packet):
#     """
#     Sniff packets and apply firewall rules.
#     """
#     if firewall_rules(packet) and rate_limit(packet):
#         # If packet passes the firewall, print its summary
#         print("Packet passed:", packet.summary())
#     else:
#         # Otherwise, print that it's blocked (no further action is taken for simplicity)
#         print("Packet blocked", packet.summary())
#
#
# # Start sniffing packets. Adjust the filter as needed (e.g., "ip" for just IP packets).
# sniff(prn=packet_sniffer, filter="tcp port 80", store=False)

from scapy.all import *
import re
import time

# Dictionary to hold packet count per IP
packet_counts = {}
# Time to reset counts, in seconds
RESET_INTERVAL = 30
# Maximum allowed packets per IP within the reset interval
RATE_LIMIT = 10
# Time when we last reset the counts
last_reset_time = time.time()

BLACKLISTED_IPS = []

def is_blacklisted_ip(packet):
    """
    Check if the source IP is blacklisted.
    """
    src_ip = packet[IP].src
    if src_ip in BLACKLISTED_IPS:
        print(f"Blocking blacklisted IP: {src_ip}")
        return True
    return False

def rate_limit(packet):
    """
    Implement rate limiting for incoming packets.
    """
    global last_reset_time
    # Check for the current time and reset if needed
    current_time = time.time()
    if current_time - last_reset_time > RESET_INTERVAL:
        packet_counts.clear()
        last_reset_time = current_time

    # Get source IP address
    src_ip = packet[IP].src
    if src_ip in packet_counts:
        packet_counts[src_ip] += 1
    else:
        packet_counts[src_ip] = 1

    # Check if the source IP has exceeded the rate limit
    if packet_counts[src_ip] > RATE_LIMIT:
        print(f"Rate limit exceeded for {src_ip}. Packet blocked.")
        return False  # Block the packet

    return True  # Allow the packet

def firewall_rules(packet):
    """
    Define firewall rules.
    This example blocks outgoing HTTP traffic (port 80) and SQL injection attempts.
    """
    src_ip = packet[IP].src

    # Check if the packet is a TCP packet and destined for port 80
    if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
        # Check if the packet has a Raw layer (this is where HTTP data is)
        http_payload = packet[Raw].load.decode('utf-8', errors='ignore')
        # Check if the payload is an HTTP GET request with a SQL injection attempt
        if http_payload.startswith('GET') and is_potential_sql_injection(http_payload):
            print("Blocking SQL injection attempt.")
            return False  # Indicate that this packet should be blocked
        if http_payload.startswith('GET') and is_potential_file_inclusion(http_payload):
            print("Blocking file inclusion attempt.")
            return False
        if http_payload.startswith('GET') and is_blacklisted_ip(packet):
            print("Blocking Blacklisted IP.")
            return False

    # New: Basic analysis of POST requests
    if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
        http_payload = packet[Raw].load.decode('utf-8', errors='ignore')  # Decode with error handling
        if http_payload.startswith('POST'):
            print("Detected HTTP POST request.")
            # This is where you'd look for CSRF tokens in a real scenario
            # For simulation, you might log a warning if expected token patterns are missing:
            if "csrf_token" not in http_payload:
                print("Warning: Possible missing CSRF protection in POST request.")
                return False  # Indicate that this packet should be blocked

    return True  # Indicate that this packet passes the firewall

def is_potential_sql_injection(payload):
    """
    Enhances detection for specific SQL injection examples.
    """
    patterns = [
        r"1=1",  # Tautology, checking specifically for "1=1"
        r"--",  # Commenting out the rest of the SQL command
        r"(?i)\bUNION\b.*\bSELECT\b",  # UNION SELECT to retrieve data from other tables
        # Additional patterns for common SQL injection techniques:
        r"(?i)\bINSERT\b.+?\bINTO\b.+?\bVALUES\b",  # Detecting attempts to insert data
        r"(%27)|(')",  # Detecting single quote characters, common in SQLi
        # Detect administrator'-- pattern specifically for subverting logic:
        r"(?i)administrator'--",
    ]
    for pattern in patterns:
        if re.search(pattern, payload):
            src_ip = packet[IP].src
            BLACKLISTED_IPS.append(src_ip)
            return True
    return False

def is_potential_file_inclusion(payload):
    """
    Enhances detection for specific file inclusion examples.
    """
    patterns = [
        r"etc/passwd",  # Accessing the passwd file
        r"../../etc/passwd",  # Traversal to access passwd file
        r"php://input",  # PHP input wrapper
        r"php://filter",  # PHP filter wrapper
        r"expect://ls",  # Using expect to execute commands
        r"file:///etc/passwd",  # File inclusion with file://
        r"auto_prepend_file",  # PHP auto_prepend_file
    ]
    for pattern in patterns:
        if re.search(pattern, payload):
            src_ip = packet[IP].src
            BLACKLISTED_IPS.append(src_ip)
            return True
    return False

def packet_sniffer(packet):
    """
    Sniff packets and apply firewall rules.
    """
    if not firewall_rules(packet) or not rate_limit(packet):
        # If packet does not pass the firewall or exceeds rate limit, print that it's blocked
        print("Packet blocked", packet.summary())
    else:
        # Otherwise, print that it passed
        print("Packet passed:", packet.summary())

# Start sniffing packets. Adjust the filter as needed (e.g., "ip" for just IP packets).
sniff(prn=packet_sniffer, filter="tcp port 80", store=False)