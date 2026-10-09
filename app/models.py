"Scan Request/response models"
import re
import socket
from typing import Optional, List, Dict
import ipaddress
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator


_PRIVATE_HOSTNAMES = {"localhost", "ip6-localhost", "ip6-loopback", "broadcasthost"}


def _lookup_hostname(hostname: str):
    """Resolve a hostname without changing DNS behavior elsewhere in the app."""
    return socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)


def _public_addresses(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve every address; an empty result is treated as unsafe by the caller."""
    try:
        literal = ipaddress.ip_address(hostname)
        return [literal]
    except ValueError:
        pass

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
        answers = _lookup_hostname(ascii_hostname)
    except (UnicodeError, socket.gaierror, OSError):
        return []

    # Keep every distinct A/AAAA result. Checking the complete answer set means
    # a hostname cannot pass merely because its first answer is public while
    # another answer points into a private or reserved network.
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for answer in answers:
        try:
            addresses.add(ipaddress.ip_address(answer[4][0].split("%", 1)[0]))
        except (IndexError, ValueError):
            continue
    return sorted(addresses, key=lambda address: (address.version, int(address)))


def _parse_public_target(target_url: str):
    """Validate the target and return its parsed URL and public DNS answers."""
    try:
        parsed = urlparse(target_url)
    except ValueError as exc:
        raise ValueError("URL is malformed") from exc

    # Validate URL syntax before doing DNS work. In particular, credentials in
    # the authority could make the apparent hostname differ from the real one.
    if not all([parsed.scheme, parsed.netloc]):
        raise ValueError("URL must include scheme (e.g. https:// or http:// )  and domain")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL scheme must be http or https")
    if re.search(r'[\n\r\x00 ]', target_url):
        raise ValueError("URL contains invalid characters")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are not allowed")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc

    hostname = parsed.hostname or ""
    normalized_hostname = hostname.lower().rstrip(".")
    if normalized_hostname in _PRIVATE_HOSTNAMES:
        raise ValueError(
            "IP address is in a private or reserved range, not allowed for security reasons"
        )

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("URL contains an invalid hostname") from exc

    # Resolve now and fail closed: DNS errors, empty answers, and any non-global
    # address reject the whole hostname rather than selecting a safer-looking
    # answer from a mixed public/private response.
    addresses = _public_addresses(ascii_hostname)
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError(
            "URL resolves to a private or reserved range; only globally routable addresses are allowed"
        )

    return parsed, ascii_hostname, port, addresses


def resolve_target_for_scan(target_url: str) -> tuple[str, str | None, str | None, int]:
    """Pin a hostname to a validated public IP for the duration of a Nuclei scan.

    Nuclei receives a literal IP, so it cannot resolve a hostname again after
    validation. Host and SNI retain virtual-host routing for DNS-name targets.
    """
    parsed, hostname, port, addresses = _parse_public_target(target_url)
    try:
        ip_literal = ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        ip_literal = None

    if ip_literal is not None:
        return target_url, None, None, ip_literal.version

    # Choose a deterministic validated address. The caller passes this literal
    # IP to Nuclei so a second DNS lookup cannot change the connection target.
    address = addresses[0]
    ip_text = address.compressed
    if address.version == 6:
        ip_text = f"[{ip_text}]"

    default_port = 80 if parsed.scheme == "http" else 443
    pinned_netloc = ip_text + (f":{port}" if port is not None else "")
    pinned_url = parsed._replace(netloc=pinned_netloc).geturl()

    # Preserve virtual-host routing after replacing the network destination
    # with an IP literal: HTTP Host selects the site and TLS SNI selects its cert.
    host_header = hostname.rstrip(".")
    if port is not None and port != default_port:
        host_header = f"{host_header}:{port}"
    tls_sni = hostname.rstrip(".") if parsed.scheme == "https" else None
    return pinned_url, host_header, tls_sni, address.version

class ScanRequest(BaseModel):
    """
    Represents the expected structure of the JSON payload for initiating a scan.
    The target_url field is validated to ensure it includes a valid scheme (http or https) and a network location (domain).
    It also checks for the presence of characters that are never valid in URLs (like newlines or null bytes) to prevent malformed input.
    This validation helps ensure that the API receives well-formed URLs, which can prevent errors during scanning and reduce the risk of certain types of injection attacks.

    """
    target_url: str = Field(
        ...,
        description= "The URL to be scanned. Must include the scheme (http:// or https://) and a valid domain",
        examples = [
            "https://example.com",
            # "http://testsite.local",
            "https://subdomain.example.com/path?query=param#fragment"
            # "http://192.168.1.1:8080"
        ]
        
    )
    
    @field_validator('target_url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        _parse_public_target(v)
        return v
       

class ScanResponse(BaseModel):
    scan_id: str = Field(
        ..., 
        description="Unique identifier for the scan, returned when a scan is initiated. Used to check status and retrieve results."
    )
    target: Optional[str] = Field(
        default=None,
        description="The URL that was scanned. Included in responses for traceability, " \
        "but may be omitted in some error cases where the scan couldn't be initiated properly."
    )  
    status: str = Field(
        ..., 
        description="Current status of the scan. Possible values: in_progress, completed, failed"
    )
    results: Optional[List[Dict]] = Field(
        default=None,
        description="List of vulnerability findings from the scan. Each finding is a dictionary containing details about the vulnerability. " \
        "This field is included in completed scans and may be omitted or null in in-progress or failed scans."
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if the scan failed. Null if the scan is in progress or completed successfully."
    )
