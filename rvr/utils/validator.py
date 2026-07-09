"""
RVR — Target validation
"""

import re
import ipaddress
from typing import Optional


def validate_target(target: str) -> Optional[str]:
    """
    Validate and classify the target.
    Returns: "ip", "subnet", "domain", or None if invalid
    """
    target = target.strip()

    # Check for subnet (CIDR notation)
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return "subnet"
        except ValueError:
            return None

    # Check for IP address
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    # Check for domain name
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}$'
    )
    if domain_pattern.match(target):
        return "domain"

    return None


def is_domain(target: str) -> bool:
    return validate_target(target) == "domain"


def is_ip(target: str) -> bool:
    return validate_target(target) in ("ip", "subnet")
