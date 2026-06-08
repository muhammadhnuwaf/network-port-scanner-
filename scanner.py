"""
PROJECT: Network Port Scanner
AUTHOR: Muhammadh Nuwaf
COURSE: Pearson BTEC HND in Computing (Cyber Security)
MODULE: Network Security / Python for Security
DATE: June 2026

PURPOSE:
This tool scans a target IP or domain to identify open ports.
In cybersecurity, port scanning helps understand a system's attack surface
- what services are running and potentially vulnerable.

DISCLAIMER:
This tool is for educational purposes and authorised testing only.
Unauthorised scanning violates computer misuse laws.
"""

import socket
import time
from datetime import datetime

services = {
    # File Transfer & Remote Access
    20: "FTP-Data",    # File transfer data channel
    21: "FTP",         # File transfer control
    22: "SSH",         # Secure shell (remote admin)
    23: "Telnet",      # Insecure remote access (avoid!)
    
    # Email Services
    25: "SMTP",        # Sending emails
    110: "POP3",       # Receiving emails (old)
    143: "IMAP",       # Receiving emails (modern)
    
    # Web Services
    53: "DNS",         # Domain name resolution
    80: "HTTP",        # Normal web traffic
    443: "HTTPS",      # Encrypted web traffic
    8080: "HTTP-Alt",  # Alternative web port
    8443: "HTTPS-Alt", # Alternative secure web
    
    # Database & Management
    3306: "MySQL",     # MySQL database
    5432: "PostgreSQL",# PostgreSQL database
    3389: "RDP",       # Windows Remote Desktop
    445: "SMB",        # Windows file sharing
    5900: "VNC",       # Remote desktop (alternative)
}

def get_service(port):
    """
    STUDENT NOTE: This function returns the service name for a given port.
    If the port isn't in our dictionary, it returns "Unknown".
    In real pentesting, you'd use banner grabbing for better accuracy.
    """
    return services.get(port, "Unknown")

# PROGRAM STARTS HERE

print("=" * 60)
print("    PROFESSIONAL PORT SCANNER")
print("    Muhammadh Nuwaf - HND Cyber Security")
print("=" * 60)

# STEP 1: Get target from user
target = input("Enter IP or domain (e.g., scanme.nmap.org or 192.168.1.1): ")

# Validate that the target exists (resolves to an IP address)
try:
    socket.gethostbyname(target)
    print(f"✅ Target resolved successfully: {target}\n")
except:
    print("❌ Error: Could not resolve hostname. Please check the address.")
    input("Press Enter to exit...")
    exit()

# STEP 2: Get port range with error handling

# STUDENT NOTE: Ports range from 1 to 65535.
# - 1-1023: Well-known ports (system services)
# - 1024-49151: Registered ports (applications)
# - 49152-65535: Dynamic/private ports

while True:
    try:
        start_port = int(input("Enter START port (1-65535): "))
        end_port = int(input("Enter END port (1-65535): "))
        
        if start_port < 1 or end_port > 65535:
            print("❌ Error: Ports must be between 1 and 65535\n")
        elif start_port > end_port:
            print("❌ Error: Start port cannot be greater than end port\n")
        else:
            break
    except ValueError:
        print("❌ Error: Please enter valid numbers only\n")


# STEP 3: Perform the scan
print(f"\n🔍 Scanning {target} from port {start_port} to {end_port}")
print("⏳ Scanning in progress... (this may take a while)")
print("💡 Tip: Scan smaller ranges like 1-100 for faster results\n")

open_ports = []      # List to store found open ports
start_time = time.time()   # Start timer for performance measurement

# Loop through each port in the specified range
for port in range(start_port, end_port + 1):
    try:
        # Create a TCP socket (AF_INET = IPv4, SOCK_STREAM = TCP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set timeout to 0.3 seconds - if no response, assume closed
        # Smaller timeout = faster scan, but may miss slow services
        sock.settimeout(0.3)
        
        # connect_ex() returns 0 if successful, error code if not
        # This is better than connect() because it doesn't throw exceptions
        result = sock.connect_ex((target, port))
        
        if result == 0:   # Port is open!
            service = get_service(port)
            print(f"  ✅ Port {port:5d} - OPEN    ({service})")
            open_ports.append(port)
        
        sock.close()  # Always close the socket to free resources
        
        # Show progress every 50 ports (so user knows it's still working)
        if port % 50 == 0:
            print(f"     [Progress: {port}/{end_port} ports scanned...]", end="\r")
            
    except KeyboardInterrupt:
        # Allow user to cancel with Ctrl+C
        print("\n\n⚠️ Scan interrupted by user (Ctrl+C pressed)")
        break
    except:
        # Catch any other network errors
        print("\n❌ Network error occurred - check your connection")
        break

end_time = time.time()
duration = end_time - start_time

# STEP 4: Display results

print("\n" + "=" * 60)
print("SCAN COMPLETE")
print("=" * 60)

if open_ports:
    print(f"✅ Found {len(open_ports)} open port(s) in {duration:.2f} seconds:\n")
    print("   PORT    SERVICE")
    print("   " + "-" * 30)
    for port in open_ports:
        print(f"   {port:5d}    {get_service(port)}")
else:
    print("❌ No open ports found in the specified range")
    print("   Possible reasons:")
    print("   • A firewall is blocking the scan")
    print("   • The target is offline")
    print("   • All ports are filtered/closed")

print(f"\n⏱️  Total scan time: {duration:.2f} seconds")
print(f"📅 Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# STEP 5: Save results to file (optional)

save = input("\n💾 Save results to file? (y/n): ").lower()
if save == 'y':
    # Create a safe filename (replace dots with underscores)
    safe_target = target.replace('.', '_')
    filename = f"port_scan_{safe_target}_{start_port}-{end_port}.txt"
    
    with open(filename, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("PORT SCAN REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Student: Muhammadh Nuwaf\n")
        f.write(f"Target: {target}\n")
        f.write(f"Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Port Range: {start_port} - {end_port}\n")
        f.write(f"Scan Duration: {duration:.2f} seconds\n")
        f.write(f"Open Ports Found: {len(open_ports)}\n\n")
        
        if open_ports:
            f.write("OPEN PORTS DETAILS:\n")
            f.write("-" * 40 + "\n")
            f.write(f"{'PORT':<8} {'SERVICE':<15} {'RISK NOTE':<20}\n")
            f.write("-" * 40 + "\n")
            for port in open_ports:
                service = get_service(port)
                # Add basic risk notes for educational purposes
                if port in [21, 23, 25, 80, 110, 143, 445]:
                    risk = "Potential risk"
                elif port in [22, 443, 3389]:
                    risk = "Monitor access"
                else:
                    risk = "Investigate"
                f.write(f"{port:<8} {service:<15} {risk:<20}\n")
        else:
            f.write("No open ports were discovered.\n")
        
        f.write("\n" + "=" * 60 + "\n")
        f.write("DISCLAIMER: This scan was performed for educational purposes\n")
        f.write("on authorised targets only.\n")
    
    print(f"✅ Report saved to: {filename}")
    print(f"   Location: {__file__} folder")

# STUDENT REFLECTION (for coursework/portfolio)

print("\n" + "=" * 60)
print("📚 WHAT I LEARNED FROM THIS PROJECT:")
print("=" * 60)
print("  1. TCP handshake and how ports work (SYN, SYN-ACK, RST)")
print("  2. Python socket programming for network tools")
print("  3. Timeout management for performance tuning")
print("  4. Error handling for robust security tools")
print("  5. Common port numbers and their services (exam prep)")
print("  6. Why port scanning is the first step in reconnaissance")
print("\n🔐 Next steps for improvement:")
print("  • Add threading for faster scanning (like Nmap)")
print("  • Add banner grabbing to identify service versions")
print("  • Create a GUI version using tkinter")
print("  • Add OS fingerprinting")

input("\nPress Enter to exit...")
