"""DNS Fuzzer Client Module.

This module provides the client-side functionality for DNS fuzzing,
including DNS query generation, mutation, and sending to target servers.
"""

from .client import DNSFuzzerClient
from .config import ClientConfig

__all__ = ['DNSFuzzerClient', 'ClientConfig']