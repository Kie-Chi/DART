"""Basic DNS mutation strategies."""

import random
from typing import override

from .. import constants
from .base import BaseMutationStrategy
from ..core.query import DNSQuery


class RandomQueryNameStrategy(BaseMutationStrategy):
    """Mutate the query name with random values."""
    
    def __init__(self):
        super().__init__(
            name="random_query_name",
            description="Replace query name with random domain name",
            weight=2.0
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to requests (queries), not responses."""
        return not query.is_response

    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        labels = rng.randint(1, 5)
        levels = None
        if rng.choice([True, False]):
            levels = { 1: "com", }
        elif rng.choice([True, False]):
            levels = {}
        mutated.qname = self.random_domain_name(
            rng, 
            max_labels=labels, 
            levels=levels
        )
        return mutated


class RandomQueryTypeStrategy(BaseMutationStrategy):
    """Mutate the query type with random values."""
    
    def __init__(self):
        super().__init__(
            name="random_query_type",
            description="Replace query type with random type",
            weight=1.5
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to requests (queries), not responses."""
        return not query.is_response
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        query_types = constants.DEFAULT_RECORD_TYPE
        mutated.qtype = rng.choice(query_types)
        return mutated


class RandomQueryClassStrategy(BaseMutationStrategy):
    """Mutate the query class with random values."""
    
    def __init__(self):
        super().__init__(
            name="random_query_class",
            description="Replace query class with random class",
            weight=1.0
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy can apply to both requests and responses."""
        return True
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        query_classes = constants.DEFAULT_CLASS_TYPE + ["Any"]
        mutated.qclass = rng.choice(query_classes)
        return mutated


class RandomQueryIdStrategy(BaseMutationStrategy):
    """Mutate the query ID with random values."""
    
    def __init__(self):
        super().__init__(
            name="random_query_id",
            description="Replace query ID with random value",
            weight=1.0
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy can apply to both requests and responses."""
        return True
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        mutated.query_id = self.mutate_numeric_field(rng, query.query_id, 0, 65535)
        return mutated


class BoundaryQueryIdStrategy(BaseMutationStrategy):
    """Test boundary values for query ID."""
    
    def __init__(self):
        super().__init__(
            name="boundary_query_id",
            description="Set query ID to boundary values (0, 65535, etc.)",
            weight=0.8
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy can apply to both requests and responses."""
        return True
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        boundary_values = [0, 1, 32767, 32768, 65534, 65535]
        mutated.query_id = rng.choice(boundary_values)
        return mutated


class LongQueryNameStrategy(BaseMutationStrategy):
    """Generate extremely long query names to test limits."""
    
    def __init__(self):
        super().__init__(
            name="long_query_name",
            description="Generate very long query names to test parsing limits",
            weight=0.5
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to requests (queries), not responses."""
        return not query.is_response
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()

        # Generate long domain name (DNS limit is 253 characters total)
        strategies = kwargs.get(
            "strategies", constants.DEFAULT_LONG_QUERY_NAME_STRATEGY
        )
        strategy = rng.choice(strategies)
        
        if strategy == "single_long_label":
            # Single label close to 63 character limit
            label_length = rng.randint(60, 70)  # May exceed limit
            long_label = self.random_string(rng, label_length)
            mutated.qname = f"{long_label}.com"
        elif strategy == "many_labels":
            # Many labels
            num_labels = rng.randint(10, 30)
            labels = []
            for _ in range(num_labels):
                label = self.random_string(rng, rng.randint(3, 10))
                labels.append(label)
            mutated.qname = '.'.join(labels)
        else:  # max_length
            # Try to reach maximum total length
            target_length = rng.randint(250, 300)  # May exceed limit
            labels = []
            current_length = 0
            
            while current_length < target_length:
                remaining = target_length - current_length
                label_length = min(rng.randint(3, 15), remaining - 1)  # -1 for dot
                if label_length <= 0:
                    break
                label = self.random_string(rng, label_length)
                labels.append(label)
                current_length += len(label) + 1  # +1 for dot
            
            mutated.qname = '.'.join(labels)
        
        return mutated


class InvalidCharacterStrategy(BaseMutationStrategy):
    """Insert invalid characters in query name."""
    
    def __init__(self):
        super().__init__(
            name="invalid_characters",
            description="Insert invalid characters in query name",
            weight=0.7
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to requests (queries), not responses."""
        return not query.is_response
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Characters that might cause issues
        invalid_chars = constants.DEFAULT_INVALID_CHAR
        
        # Choose insertion strategy
        strategies = kwargs.get(
            "strategies", constants.DEFULAT_INVALID_CHAR_STRATEGY
        )
        strategy = rng.choice(strategies)
        
        original_name = query.qname
        invalid_char = rng.choice(invalid_chars)
        
        if strategy == "replace_char" and original_name:
            # Replace random character
            pos = rng.randint(0, len(original_name) - 1)
            mutated.qname = original_name[:pos] + invalid_char + original_name[pos+1:]
        elif strategy == "insert_char":
            # Insert at random position
            pos = rng.randint(0, len(original_name))
            mutated.qname = original_name[:pos] + invalid_char + original_name[pos:]
        else:  # append_char
            # Append invalid character
            mutated.qname = original_name + invalid_char
        
        return mutated


class EmptyFieldStrategy(BaseMutationStrategy):
    """Set various fields to empty values."""
    
    def __init__(self):
        super().__init__(
            name="empty_fields",
            description="Set query name or other fields to empty values",
            weight=0.6
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy can apply to both requests and responses."""
        return True
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Choose what to make empty
        empty_targets = kwargs.get(
            "targets", constants.DEFAULT_EMPTY_FILED_TYPE
        )
        target = rng.choice(empty_targets)
        
        if target == "qname":
            mutated.qname = ""
        elif target == "qtype":
            mutated.qtype = ""
        elif target == "qclass":
            mutated.qclass = ""
        
        return mutated


class CaseVariationStrategy(BaseMutationStrategy):
    """Vary the case of query name."""
    
    def __init__(self):
        super().__init__(
            name="case_variation",
            description="Randomly vary case of characters in query name",
            weight=1.2
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy can apply to both requests and responses."""
        return True
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Apply case variations
        strategies = kwargs.get(
            "strategies", constants.DEFAULT_CASE_STRATEGY
        )
        strategy = rng.choice(strategies)
        
        original_name = query.qname
        
        if strategy == "all_upper":
            mutated.qname = original_name.upper()
        elif strategy == "all_lower":
            mutated.qname = original_name.lower()
        elif strategy == "random_case":
            # Randomly change case of each character
            result = ""
            for char in original_name:
                if char.isalpha():
                    if rng.choice([True, False]):
                        result += char.upper()
                    else:
                        result += char.lower()
                else:
                    result += char
            mutated.qname = result
        else:  # alternating
            # Alternate between upper and lower case
            result = ""
            upper = True
            for char in original_name:
                if char.isalpha():
                    if upper:
                        result += char.upper()
                    else:
                        result += char.lower()
                    upper = not upper
                else:
                    result += char
            mutated.qname = result
        
        return mutated


class NumericQueryNameStrategy(BaseMutationStrategy):
    """Generate numeric-only query names."""
    
    def __init__(self):
        super().__init__(
            name="numeric_query_name",
            description="Generate query names with only numeric characters",
            weight=0.8
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to requests (queries), not responses."""
        return not query.is_response
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Generate numeric domain name
        num_labels = rng.randint(1, 4)
        labels = []
        
        for _ in range(num_labels):
            label_length = rng.randint(1, 10)
            numeric_label = ''.join(str(rng.randint(0, 9)) for _ in range(label_length))
            labels.append(numeric_label)
        
        mutated.qname = '.'.join(labels)
        return mutated


class SpecialDomainStrategy(BaseMutationStrategy):
    """Use special/reserved domain names."""
    
    def __init__(self):
        super().__init__(
            name="special_domains",
            description="Use special or reserved domain names",
            weight=0.9
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy can apply to both requests and responses."""
        return True
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random) -> DNSQuery:
        mutated = query.clone()
        
        # Special domain names that might trigger different behavior
        special_domains = constants.DEFAULT_SPECIAL_DOMAIN
        
        mutated.qname = rng.choice(special_domains)
        return mutated