"""DNS resource record mutation strategies."""

import random
from typing import override

from .. import constants
from .base import BaseMutationStrategy
from ..core.query import DNSQuery


class RandomRecordTypeStrategy(BaseMutationStrategy):
    """Mutate record types in answers, authorities, and additional sections."""
    
    def __init__(self):
        super().__init__(
            name="random_record_type",
            description="Change record types to random or invalid values",
            weight=1.2
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        return bool(query.answers or query.authorities or query.additional)
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        mutated = query.clone()
        
        # Common and uncommon record types
        record_types = constants.DEFAULT_RECORD_TYPE
        
        # Mutate records in all sections
        for section_name in ['answers', 'authorities', 'additional']:
            section = getattr(mutated, section_name)
            if section:
                for record in section:
                    if rng.choice([True, False]):  # 50% chance to mutate each record
                        record['type'] = rng.choice(record_types)
        
        return mutated


class InvalidRecordDataStrategy(BaseMutationStrategy):
    """Create records with invalid or malformed data."""
    
    def __init__(self):
        super().__init__(
            name="invalid_record_data",
            description="Generate records with invalid or malformed rdata",
            weight=1.0
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        return bool(query.answers or query.authorities or query.additional)
    
    def mutate(self, query: DNSQuery, rng: random.Random) -> DNSQuery:
        mutated = query.clone()
        
        # Invalid data patterns
        invalid_patterns = [
            "",  # Empty data
            "invalid",  # Generic invalid string
            "256.256.256.256",  # Invalid IP
            "::invalid::",  # Invalid IPv6
            "a" * 1000,  # Too long
            "\x00\x01\x02",  # Binary data
            "test..example.com",  # Double dots
            ".example.com",  # Leading dot
            "example.com.",  # Trailing dot (might be valid in some contexts)
            "very-long-" + "a" * 100 + ".example.com",  # Very long label
        ]
        
        # Mutate records in all sections
        for section_name in ['answers', 'authorities', 'additional']:
            section = getattr(mutated, section_name)
            if section:
                for record in section:
                    if rng.choice([True, False]):  # 50% chance to mutate each record
                        record['rdata'] = rng.choice(invalid_patterns)
        
        return mutated


class RecordTTLMutationStrategy(BaseMutationStrategy):
    """Mutate TTL values in resource records."""
    
    def __init__(self):
        super().__init__(
            name="record_ttl_mutation",
            description="Set unusual or invalid TTL values",
            weight=0.8
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        return bool(query.answers or query.authorities or query.additional)
    
    def mutate(self, query: DNSQuery, rng: random.Random) -> DNSQuery:
        mutated = query.clone()
        
        # Special TTL values
        special_ttls = [
            0,          # No caching
            1,          # Very short
            2147483647, # Maximum signed 32-bit
            4294967295, # Maximum unsigned 32-bit
            -1,         # Negative (invalid)
            86400,      # 1 day (common)
            604800,     # 1 week (common)
            31536000,   # 1 year (long)
        ]
        
        # Mutate records in all sections
        for section_name in ['answers', 'authorities', 'additional']:
            section = getattr(mutated, section_name)
            if section:
                for record in section:
                    if rng.choice([True, False]):  # 50% chance to mutate each record
                        record['ttl'] = rng.choice(special_ttls)
        
        return mutated


class DuplicateRecordStrategy(BaseMutationStrategy):
    """Create duplicate records in response sections."""
    
    def __init__(self):
        super().__init__(
            name="duplicate_records",
            description="Add duplicate records to response sections",
            weight=0.7
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        return bool(query.answers or query.authorities or query.additional)
    
    def mutate(self, query: DNSQuery, rng: random.Random) -> DNSQuery:
        mutated = query.clone()
        
        # Choose a section to duplicate records in
        sections_with_records = []
        if mutated.answers:
            sections_with_records.append('answers')
        if mutated.authorities:
            sections_with_records.append('authorities')
        if mutated.additional:
            sections_with_records.append('additional')
        
        if not sections_with_records:
            return mutated
        
        section_name = rng.choice(sections_with_records)
        section = getattr(mutated, section_name)
        
        # Duplicate some records
        records_to_duplicate = rng.sample(section, min(len(section), rng.randint(1, 3)))
        
        for record in records_to_duplicate:
            # Create duplicate with slight variations
            duplicate = record.copy()
            
            # Sometimes modify the duplicate slightly
            if rng.choice([True, False]):
                if 'ttl' in duplicate:
                    duplicate['ttl'] = rng.randint(0, 86400)
            
            section.append(duplicate)
        
        return mutated


class EmptyRecordSectionStrategy(BaseMutationStrategy):
    """Create responses with empty record sections."""
    
    def __init__(self):
        super().__init__(
            name="empty_record_sections",
            description="Clear record sections in responses",
            weight=0.6
        )
    
    def mutate(self, query: DNSQuery, rng: random.Random) -> DNSQuery:
        mutated = query.clone()
        
        # Make it a response if it isn't already
        mutated.is_response = True
        
        # Choose which sections to empty
        sections_to_empty = rng.choices(
            ['answers', 'authorities', 'additional'],
            k=rng.randint(1, 3)
        )
        
        for section_name in sections_to_empty:
            setattr(mutated, section_name, [])
        
        return mutated


class MismatchedRecordStrategy(BaseMutationStrategy):
    """Create records that don't match the query."""
    
    def __init__(self):
        super().__init__(
            name="mismatched_records",
            description="Add records that don't match the original query",
            weight=1.0
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to responses or packets that can be converted to responses."""
        return query.is_response or bool(query.answers or query.authorities or query.additional)
    
    def mutate(self, query: DNSQuery, rng: random.Random) -> DNSQuery:
        mutated = query.clone()
        
        # Make it a response
        mutated.is_response = True
        
        # Generate mismatched records
        mismatched_records = []
        
        for _ in range(rng.randint(1, 3)):
            record = {
                'name': self.random_domain_name(rng),  # Different name
                'type': rng.choice(['A', 'AAAA', 'CNAME', 'MX', 'TXT']),  # Potentially different type
                'class': rng.choice(['IN', 'CH', 'HS']),  # Potentially different class
                'ttl': rng.randint(0, 86400),
                'rdata': self.random_string(rng)
            }
            mismatched_records.append(record)
        
        # Add to answers section
        mutated.answers.extend(mismatched_records)
        
        return mutated


class LargeRecordStrategy(BaseMutationStrategy):
    """Create unusually large records."""
    
    def __init__(self):
        super().__init__(
            name="large_records",
            description="Create records with large data fields",
            weight=1.0
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to responses or packets that can be converted to responses."""
        return query.is_response or bool(query.answers or query.authorities or query.additional)
    
    def mutate(self, query: DNSQuery, rng: random.Random) -> DNSQuery:
        mutated = query.clone()
        
        # Make it a response
        mutated.is_response = True
        
        # Create large records
        large_records = []
        
        for _ in range(rng.randint(1, 2)):  # Don't create too many large records
            # Choose record type that can handle large data
            record_type = rng.choice(['TXT', 'CNAME', 'NS', 'PTR'])
            
            # Generate large data
            if record_type == 'TXT':
                # TXT records can be quite large
                large_data = self.random_string(rng, length=rng.randint(500, 2000))
            else:
                # For other types, create long domain names
                labels = []
                total_length = 0
                while total_length < 200 and len(labels) < 10:  # DNS name limit is 255 bytes
                    label = self.random_string(rng, length=rng.randint(10, 50))
                    labels.append(label)
                    total_length += len(label) + 1  # +1 for dot
                
                large_data = '.'.join(labels) + '.example.com'
            
            record = {
                'name': mutated.qname,
                'type': record_type,
                'class': mutated.qclass,
                'ttl': rng.randint(0, 86400),
                'rdata': large_data
            }
            large_records.append(record)
        
        mutated.answers.extend(large_records)
        
        return mutated


class RecordCompressionStrategy(BaseMutationStrategy):
    """Test DNS name compression edge cases."""
    
    def __init__(self):
        super().__init__(
            name="record_compression",
            description="Test DNS name compression and decompression",
            weight=1.0
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to responses or packets that can be converted to responses."""
        return query.is_response or bool(query.answers or query.authorities or query.additional)
    
    def mutate(self, query: DNSQuery, rng: random.Random) -> DNSQuery:
        mutated = query.clone()
        
        # Make it a response
        mutated.is_response = True
        
        # Create records with repeated names to trigger compression
        base_name = mutated.qname
        
        compression_records = []
        
        # Create multiple records with the same or similar names
        for i in range(rng.randint(3, 6)):
            # Use variations of the base name
            if rng.choice([True, False]):
                name = base_name
            else:
                # Create subdomain
                subdomain = self.random_string(rng, length=rng.randint(3, 10))
                name = f"{subdomain}.{base_name}"
            
            record_type = rng.choice(['A', 'AAAA', 'CNAME', 'NS'])
            
            # Generate appropriate rdata based on record type
            if record_type == 'A':
                rdata = self.random_ipv4(rng)
            elif record_type == 'AAAA':
                rdata = self.random_ipv6(rng)
            elif record_type in ['CNAME', 'NS']:
                rdata = self.random_domain_name(rng)
            else:
                rdata = self.random_ipv4(rng)  # fallback
            
            record = {
                'name': name,
                'type': record_type,
                'class': 'IN',
                'ttl': rng.randint(0, 86400),
                'rdata': rdata
            }
            compression_records.append(record)
        
        mutated.answers.extend(compression_records)
        
        return mutated


class WildcardRecordStrategy(BaseMutationStrategy):
    """Test wildcard record handling."""
    
    def __init__(self):
        super().__init__(
            name="wildcard_records",
            description="Create wildcard records and test wildcard handling",
            weight=1.0
        )
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to responses or packets that can be converted to responses."""
        return query.is_response or bool(query.answers or query.authorities or query.additional)
    
    def mutate(self, query: DNSQuery, rng: random.Random) -> DNSQuery:
        mutated = query.clone()
        
        # Make it a response
        mutated.is_response = True
        
        # Create wildcard records
        wildcard_patterns = [
            "*.example.com",
            "*." + mutated.qname,
            "*.*.example.com",
            "*",  # Root wildcard (unusual)
            "test.*.example.com",  # Wildcard in middle (invalid)
        ]
        
        wildcard_records = []
        
        for _ in range(rng.randint(1, 3)):
            record = {
                'name': rng.choice(wildcard_patterns),
                'type': rng.choice(['A', 'AAAA', 'CNAME', 'TXT']),
                'class': 'IN',
                'ttl': rng.randint(0, 86400),
                'rdata': self.random_ipv4(rng)
            }
            wildcard_records.append(record)
        
        mutated.answers.extend(wildcard_records)
        
        return mutated