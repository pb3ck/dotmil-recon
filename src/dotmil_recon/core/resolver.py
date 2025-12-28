import socket


def check_live(domain: str, timeout: float = 60.0) -> bool:
    """Check if a domain resolves to an IP address."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False