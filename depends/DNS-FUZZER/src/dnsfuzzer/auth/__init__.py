"""DNS Fuzzer Auth Server Module.

This module provides the authoritative server-side functionality for DNS fuzzing,
including DNS request processing, response generation, and mutation.
"""

from .server import DNSAuthServer
from .config import AuthConfig

__all__ = ['DNSAuthServer', 'AuthConfig']