"""Core DNS fuzzing components."""

from .query import DNSQuery, DNSQueryBuilder
from .mutator import MutationStrategy, DNSMutator

__all__ = [
    "DNSQuery",
    "DNSQueryBuilder",
    "MutationStrategy", 
    "DNSMutator",
]