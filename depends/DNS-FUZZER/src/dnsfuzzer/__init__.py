"""DNS Fuzzer - A Python-based DNS fuzzing tool with pluggable mutation strategies."""

__version__ = "0.1.0"
__author__ = "DNS Fuzzer Team"

from .core.query import DNSQuery, DNSQueryBuilder
from .core.mutator import MutationStrategy, DNSMutator
from .strategies.base import BaseMutationStrategy

__all__ = [
    "DNSQuery",
    "DNSQueryBuilder", 
    "MutationStrategy",
    "DNSMutator",
    "BaseMutationStrategy",
]