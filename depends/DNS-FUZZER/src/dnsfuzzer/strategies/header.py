"""DNS header mutation strategies."""

import random
from typing import override 

from .. import constants
from .base import BaseMutationStrategy
from ..core.query import DNSQuery, DNSOpcode, DNSRcode


class RandomOpcodeStrategy(BaseMutationStrategy):
    """Mutate the DNS opcode field."""
    
    def __init__(self):
        super().__init__(
            name="random_opcode",
            description="Set random or invalid opcode values",
            weight=1.0
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to requests (queries), not responses."""
        return not query.is_response
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Mix of valid and potentially invalid opcodes
        opcodes = list(DNSOpcode)
        
        # Add some potentially invalid opcodes
        for i in range(6, 16):  # Opcodes 6-15 are reserved/unassigned
            try:
                opcodes.append(DNSOpcode(i))
            except ValueError:
                pass  # Skip if enum doesn't support this value
        
        mutated.opcode = rng.choice(opcodes)
        return mutated


class RandomResponseCodeStrategy(BaseMutationStrategy):
    """Mutate the DNS response code field."""
    
    def __init__(self):
        super().__init__(
            name="random_rcode",
            description="Set random or invalid response code values",
            weight=1.0
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to responses."""
        return query.is_response
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Mix of valid and potentially invalid response codes
        rcodes = list(DNSRcode)
        
        # Add some potentially invalid response codes
        for i in range(6, 16):  # Some higher values
            try:
                rcodes.append(DNSRcode(i))
            except ValueError:
                pass  # Skip if enum doesn't support this value
        
        mutated.response_code = rng.choice(rcodes)
        return mutated


class RandomFlagsStrategy(BaseMutationStrategy):
    """Mutate various DNS header flags."""
    
    def __init__(self):
        super().__init__(
            name="random_flags",
            description="Randomly set DNS header flags",
            weight=1.5
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy can apply to both requests and responses."""
        return True
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Randomly flip various flags
        flags_to_mutate = rng.choices(
            constants.DEFAULT_FLAGS_STRATEGY,
            k=rng.randint(1, 3)
        )
        
        for flag in flags_to_mutate:
            if flag == 'authoritative':
                mutated.authoritative = rng.choice([True, False])
            elif flag == 'truncated':
                mutated.truncated = rng.choice([True, False])
            elif flag == 'recursion_desired':
                mutated.recursion_desired = rng.choice([True, False])
            elif flag == 'recursion_available':
                mutated.recursion_available = rng.choice([True, False])
            elif flag == 'is_response':
                mutated.is_response = rng.choice([True, False])
        
        return mutated


class InvalidFlagCombinationStrategy(BaseMutationStrategy):
    """Create invalid or unusual flag combinations."""
    
    def __init__(self):
        super().__init__(
            name="invalid_flag_combinations",
            description="Create unusual or invalid combinations of DNS flags",
            weight=0.8
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy can apply to both requests and responses."""
        return True
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Define some unusual flag combinations
        combinations = constants.DEFAULT_FLAGS_COMB_STRATEGY
        combination = rng.choice(combinations)
        
        for flag, value in combination.items():
            setattr(mutated, flag, value)
        
        return mutated


class QueryAsResponseStrategy(BaseMutationStrategy):
    """Convert query to response format."""
    
    def __init__(self):
        super().__init__(
            name="query_as_response",
            description="Convert query packet to response format",
            weight=1.2
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to requests (queries) to convert them to responses."""
        return not query.is_response
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Set response flag
        mutated.is_response = True
        
        # Randomly set other response-related flags
        mutated.authoritative = rng.choice([True, False])
        mutated.recursion_available = rng.choice([True, False])
        
        # Optionally add answer records
        if rng.choice([True, False]):
            # Add a simple answer record
            answer_record = self._generate_record(query, rng)
            mutated.answers = [answer_record]
            while rng.randint(0, 5) != 0:
                mutated.answers.append(self._generate_record(query, rng))

        return mutated

    def _generate_record(self, query: DNSQuery, rng: random.Random) -> dict:
        return {
            "name": query.qname,
            "type": query.qtype,
            "class": query.qclass,
            "ttl": rng.randint(0, 86400),
            "rdata": self.generate_random_record(rng, [query.qtype]).get(
                "rdata", "RANDOM_IS_NONE_RECORD"
            ),
        }

class ResponseAsQueryStrategy(BaseMutationStrategy):
    """Convert response to query format."""
    
    def __init__(self):
        super().__init__(
            name="response_as_query",
            description="Convert response packet to query format",
            weight=0.8
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        # Only apply to responses or packets with answer records
        return query.is_response or query.answers or query.authorities or query.additional
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Set as query
        mutated.is_response = False
        
        # Clear response-specific flags
        mutated.authoritative = False
        mutated.recursion_available = False
        
        # Optionally clear answer sections
        if rng.choice([True, False]):
            mutated.answers = []
            mutated.authorities = []
            mutated.additional = []
        
        return mutated


class EDNSMutationStrategy(BaseMutationStrategy):
    """Mutate EDNS-related fields."""
    
    def __init__(self):
        super().__init__(
            name="edns_mutation",
            description="Mutate EDNS version, payload size, and flags",
            weight=1.0
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy can apply to both requests and responses."""
        return True
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Choose what to mutate
        strategies = kwargs.get("strategies", constants.DEFAULT_EDNS_STRATEGY)
        edns_fields = rng.choices(
            strategies,
            k=rng.randint(1, 3)
        )
        
        for field in edns_fields:
            if field == 'version':
                # EDNS version (0 is standard, others might cause issues)
                versions = [0, 1, 2, 255]  # Mix valid and invalid
                mutated.edns_version = rng.choice(versions)
            elif field == 'payload_size':
                # UDP payload size
                sizes = [
                    512,    # Minimum
                    1232,   # Common default
                    1472,   # Ethernet MTU - headers
                    4096,   # Large
                    65535,  # Maximum
                    0,      # Invalid
                    1,      # Too small
                ]
                mutated.edns_payload_size = rng.choice(sizes)
            elif field == 'dnssec_ok':
                mutated.edns_dnssec_ok = rng.choice([True, False])
        
        return mutated


class TruncatedFlagStrategy(BaseMutationStrategy):
    """Specifically test the truncated flag."""
    
    def __init__(self):
        super().__init__(
            name="truncated_flag",
            description="Set truncated flag in various contexts",
            weight=0.7
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy can apply to both requests and responses."""
        return True
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Always set truncated flag
        mutated.truncated = True
        
        # Decide context
        contexts = kwargs.get("strategies", constants.DEFAULT_TRUNCATED_CONTEXT)
        context = rng.choice(contexts)
        
        if context == "query_truncated":
            # Truncated query (unusual)
            mutated.is_response = False
        elif context == "response_truncated":
            # Truncated response (more normal)
            mutated.is_response = True
            mutated.authoritative = rng.choice([True, False])
            
            # Add some records to make truncation more realistic
            for _ in range(rng.randint(1, 3)):
                record = self.generate_random_record(rng)
                mutated.answers.append(record)
        else:  # empty_truncated
            # Truncated but no records (unusual)
            mutated.is_response = True
            mutated.answers = []
            mutated.authorities = []
            mutated.additional = []
        
        return mutated


class ZeroQueryIdStrategy(BaseMutationStrategy):
    """Set query ID to zero or other special values."""
    
    def __init__(self):
        super().__init__(
            name="zero_query_id",
            description="Set query ID to zero or other special values",
            weight=0.6
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy can apply to both requests and responses."""
        return True
    
    def mutate(self, query: DNSQuery, rng: random.Random) -> DNSQuery:
        mutated = query.clone()
        
        # Special ID values that might be handled differently
        special_ids = [0, 1, 65535, 32768, 16384]
        mutated.query_id = rng.choice(special_ids)
        
        return mutated