"""Constants for DNS Fuzzer."""

# --- Log and Debug ---
# Short aliases for module names to keep CLI/env concise
LOG_ALIAS_MAP = {
    "core": "dnsfuzzer.core",
    "query": "dnsfuzzer.core.query",
    "mutator": "dnsfuzzer.core.mutator",
    "mut": "dnsfuzzer.core.mutator",
    "config": "dnsfuzzer.core.config",
    "conf": "dnsfuzzer.core.config",
    "strategies": "dnsfuzzer.strategies",
    "strat": "dnsfuzzer.strategies",
    "basic": "dnsfuzzer.strategies.basic",
    "header": "dnsfuzzer.strategies.header",
    "record": "dnsfuzzer.strategies.record",
    "cli": "dnsfuzzer.cli",
    "utils": "dnsfuzzer.utils",
    "exceptions": "dnsfuzzer.exceptions",
    "exc": "dnsfuzzer.exceptions",
}

# Top-level modules within dnsfuzzer for auto-prefixing
KNOWN_TOP_MODULES = {
    "core",
    "strategies",
    "utils",
    "exceptions",
    "cli",
}

# --- DNS Fuzzing Constants ---
DEFAULT_TIMEOUT = 5.0
DEFAULT_PORT = 53
MAX_RETRIES = 3

# --- Fuzzing Strategy Types ---
STRATEGY_TYPES = {
    "BASIC",
    "HEADER",
    "RECORD",
    "ADVANCED",
}

DEFAULT_STRATEGY = [
    ("random_query_name", True, 1.5),
    ("random_query_type", True, 1.2),
    ("random_query_class", True, 0.8),
    ("random_query_id", True, 1.0),
    ("boundary_query_id", True, 0.7),
    ("long_query_name", True, 1.0),
    ("invalid_characters", True, 0.9),
    ("empty_fields", True, 0.6),
    ("case_variation", True, 0.8),
    ("numeric_query_name", True, 0.5),
    ("special_domains", True, 0.7),
    ("random_opcode", True, 1.0),
    ("random_rcode", True, 0.8),
    ("random_flags", True, 1.2),
    ("invalid_flag_combinations", True, 0.6),
    ("query_as_response", True, 1.0),
    ("response_as_query", True, 0.7),
    ("edns_mutation", True, 1.0),
    ("truncated_flag", True, 0.5),
    ("zero_query_id", True, 0.4),
]

# --- Mutation Types
DEFAULT_STRING_TYPE = ["replace", "append", "prepend", "truncate", "case"]

DEFAULT_NUMERIC_TYPE = ["random", "boundary", "increment", "decrement", "bit_flip"]

DEFAULT_LIST_TYPE = ["add", "remove", "modify", "shuffle", "duplicate"]

DEFAULT_RECORD_TYPE = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SOA"]

DEFAULT_CLASS_TYPE = ["IN", "CH", "HS"]

DEFAULT_LONG_QUERY_NAME_STRATEGY = ["single_long_label", "many_labels", "max_length"]

DEFAULT_INVALID_CHAR = ['\x00', '\x01', '\x1f', '\x7f', '\xff', ' ', '\t', '\n', 
                        '\\', '"', "'", '<', '>', '|', '*', '?', '/', ':']

DEFULAT_INVALID_CHAR_STRATEGY = ["replace_char", "insert_char", "append_char"]

DEFAULT_EMPTY_FILED_TYPE = ["qname", "qtype", "qclass"]

DEFAULT_CASE_STRATEGY = ["all_upper", "all_lower", "random_case", "alternating"]

DEFAULT_SPECIAL_DOMAIN = [
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "255.255.255.255",
    "example.com",
    "example.org",
    "example.net",
    "test",
    "invalid",
    "local",
    "onion",
    "exit",
    "i2p",
    "_tcp.example.com",
    "_udp.example.com",
    "*.example.com",
    "xn--nxasmq6b",  # IDN domain
    "very-long-subdomain-name-that-might-cause-issues.example.com"
]

DEFAULT_FLAGS_STRATEGY = [
    "authoritative",
    "truncated",
    "recursion_desired",
    "recursion_available",
    "is_response",
]

DEFAULT_FLAGS_COMB_STRATEGY = [
    # Query with response flags set
    {"is_response": False, "authoritative": True, "recursion_available": True},
    # Response without authoritative or recursion available
    {
        "is_response": True,
        "authoritative": False,
        "recursion_available": False,
        "truncated": True,
    },
    # All flags set
    {
        "is_response": True,
        "authoritative": True,
        "truncated": True,
        "recursion_desired": True,
        "recursion_available": True,
    },
    # No flags set (unusual for responses)
    {
        "is_response": True,
        "authoritative": False,
        "truncated": False,
        "recursion_desired": False,
        "recursion_available": False,
    },
]

DEFAULT_EDNS_STRATEGY = ["version", "payload_size", "dnssec_ok"]

DEFAULT_TRUNCATED_CONTEXT = ["query_truncated", "response_truncated", "empty_truncated"]

DEFAULT_RECORD_TYPE = [
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'TXT',
    'SRV', 'NAPTR', 'DNAME', 'DS', 'RRSIG', 'NSEC', 'NSEC3',
    'TLSA', 'CAA', 'SVCB', 'HTTPS',
    # Uncommon/experimental types
    'AFSDB', 'APL', 'CERT', 'DHCID', 'DLV', 'DNSKEY',
    'HIP', 'IPSECKEY', 'KEY', 'KX', 'LOC', 'MINFO',
    'NID', 'NIMLOC', 'NINFO', 'RKEY', 'RP', 'SIG',
    'SINK', 'TA', 'TKEY', 'TSIG', 'URI', 'X25'
]



DEFAULT_LEVELS = {
    0: "com",
    1: "example"
}

# field -> weight
DEFAULT_MUTATE_FILEDS = {
    "name": 3, 
    "type": 2, 
    "class": 1, 
    "ttl": 2, 
    "rdata": 4
}
