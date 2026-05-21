import socket
import platform
import uuid


def get_mac_address() -> str:
    """
    Extracts and formats the hardware MAC address of the primary network interface.
    """
    # uuid.getnode() fetches a 48-bit integer representing the hardware address
    mac_num = uuid.getnode()
    # Format the integer into standard 12-character hex pairs separated by colons
    mac_str = ':'.join(['{:02x}'.format((mac_num >> ele) & 0xff) for ele in range(0, 8*6, 8)][::-1])
    return mac_str

def get_machine_info() -> dict:
    """
    Gathers the primary local IPv4 address, hostname, OS details, 
    and current hardware resource utilization.
    """
    main_ipv4 = "127.0.0.1"
    hostname = socket.gethostname()
    
    # Extract the main active local IPv4 address
    try:
        # We connect to a public DNS IP (does not actually send any packets)
        # to force the OS to pick the interface facing the internet/router.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        main_ipv4 = s.getsockname()[0]
        s.close()
    except Exception:
        # Fallback if the machine is entirely offline
        try:
            main_ipv4 = socket.gethostbyname(hostname)
        except Exception:
            pass

    # Gather underlying system architecture details
    info = {
        "mac_address": get_mac_address(),
        "host_name": hostname,
        "main_ipv4": main_ipv4,
        "all_ips": [ip[4][0] for ip in socket.getaddrinfo(hostname, None) if ip[4][0]],
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine_architecture": platform.machine()
    }
    return info


if __name__ == "__main__":
    print(get_machine_info())