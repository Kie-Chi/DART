"""Exceptions module for DNS Fuzzer."""
class DNSFException(Exception):
    """Base exception class for DNS Fuzzer."""


class DNSFFuzzException(DNSFException):
    """Exception class for DNS Fuzzer fuzzing errors."""



class DNSFMutException(DNSFException):
    """Exception class for DNS Fuzzer mutation errors."""


class NoSuchStrategyError(DNSFMutException):
    """Exception class for DNS Fuzzer when a strategy is not found."""
