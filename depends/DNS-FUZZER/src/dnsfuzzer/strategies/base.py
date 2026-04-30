"""Base mutation strategy implementations."""

import random
from abc import ABC, abstractmethod
from typing import List, Any, Dict

from ..core.mutator import MutationStrategy
from ..core.query import DNSQuery
from .. import constants

class BaseMutationStrategy(MutationStrategy, ABC):
    """Base class providing common mutation utilities."""
    
    def __init__(self, name: str, description: str = "", weight: float = 1.0):
        super().__init__(name, description, weight)

    @abstractmethod
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        """Apply mutation to the given query."""
        pass
    
    def random_string(self, rng: random.Random, length: int = None, charset: str = "abcdefghijklmnopqrstuvwxyz0123456789") -> str:
        """Generate a random string."""
        if length is None:
            length = rng.randint(1, 20)
        return ''.join(rng.choices(charset, k=length))
    
    def random_domain_name(self, rng: random.Random, max_labels: int = 5, charset: str = "abcdefghijklmnopqrstuvwxyz", levels: Dict[int, str] = None) -> str:
        """Generate a random domain name."""
        if levels is None:
            levels = constants.DEFAULT_LEVELS
        num_labels = rng.randint(1, max_labels)
        labels = []
        
        for i in range(num_labels):
            if i in levels:
                label = levels[i]
            else:
                label_length = rng.randint(1, 10)
                label = self.random_string(rng, label_length, charset)
            labels.append(label)
        
        domain = '.'.join(labels)
        # Ensure domain name is absolute (ends with dot)
        if not domain.endswith('.'):
            domain += '.'
        return domain
    
    def random_ipv4(self, rng: random.Random) -> str:
        """Generate a random IPv4 address."""
        return '.'.join(str(rng.randint(0, 255)) for _ in range(4))
    
    def random_ipv6(self, rng: random.Random) -> str:
        """Generate a random IPv6 address."""
        parts = []
        for _ in range(8):
            parts.append(f"{rng.randint(0, 65535):04x}")
        return ':'.join(parts)
    
    def mutate_string_field(self, rng: random.Random, value: str, 
                           mutation_types: List[str] = None) -> str:
        """Apply various mutations to a string field."""
        if mutation_types is None:
            mutation_types = constants.DEFAULT_STRING_TYPE
        
        mutation_type = rng.choice(mutation_types)
        
        if mutation_type == "replace":
            # Replace with random string
            return self.random_string(rng, len(value))
        elif mutation_type == "append":
            # Append random characters
            suffix = self.random_string(rng, rng.randint(1, 10))
            return value + suffix
        elif mutation_type == "prepend":
            # Prepend random characters
            prefix = self.random_string(rng, rng.randint(1, 10))
            return prefix + value
        elif mutation_type == "truncate":
            # Truncate string
            if len(value) > 1:
                new_length = rng.randint(1, len(value) - 1)
                return value[:new_length]
            return value
        elif mutation_type == "case":
            # Change case
            if rng.choice([True, False]):
                return value.upper()
            else:
                return value.lower()
        else:
            return value
    
    def mutate_numeric_field(self, rng: random.Random, value: int, min_val: int = 0, max_val: int = 65535, mutation_types: List[str] = None) -> int:
        """Apply mutations to a numeric field."""
        if mutation_types is None:
            mutation_types = constants.DEFAULT_NUMERIC_TYPE
        
        mutation_type = rng.choice(mutation_types)
        
        if mutation_type == "random":
            return rng.randint(min_val, max_val)
        elif mutation_type == "boundary":
            # Test boundary values
            boundaries = [min_val, max_val, min_val + 1, max_val - 1]
            return rng.choice([b for b in boundaries if min_val <= b <= max_val])
        elif mutation_type == "increment":
            return min(value + rng.randint(1, 100), max_val)
        elif mutation_type == "decrement":
            return max(value - rng.randint(1, 100), min_val)
        elif mutation_type == "bit_flip":
            # Flip random bits
            bit_pos = rng.randint(0, 15)  # Assuming 16-bit values
            return value ^ (1 << bit_pos)
        else:
            return value
    
    def mutate_list_field(self, rng: random.Random, value_list: List[Any], item_generator=None, mutation_types: List[str] = None) -> List[Any]:
        """Apply mutations to a list field."""
        if not value_list and not item_generator:
            return value_list
        
        if mutation_types is None:
            mutation_types = constants.DEFAULT_LIST_TYPE
        
        if not value_list:
            mutation_types = ["add"]  # Can only add if list is empty
        
        mutation_type = rng.choice(mutation_types)
        new_list = value_list.copy()
        
        if mutation_type == "add" and item_generator:
            # Add new item
            new_item = item_generator(rng)
            insert_pos = rng.randint(0, len(new_list))
            new_list.insert(insert_pos, new_item)
        elif mutation_type == "remove" and new_list:
            # Remove random item
            remove_idx = rng.randint(0, len(new_list) - 1)
            new_list.pop(remove_idx)
        elif mutation_type == "modify" and new_list and item_generator:
            # Modify random item
            modify_idx = rng.randint(0, len(new_list) - 1)
            new_list[modify_idx] = item_generator(rng)
        elif mutation_type == "shuffle" and len(new_list) > 1:
            # Shuffle list
            rng.shuffle(new_list)
        elif mutation_type == "duplicate" and new_list:
            # Duplicate random item
            dup_idx = rng.randint(0, len(new_list) - 1)
            item_to_dup = new_list[dup_idx]
            insert_pos = rng.randint(0, len(new_list))
            new_list.insert(insert_pos, item_to_dup)
        
        return new_list
    
    def generate_random_record(self, rng: random.Random, record_types: List[str] = None) -> dict:
        """Generate a random DNS resource record."""
        if record_types is None:
            record_types = constants.DEFAULT_RECORD_TYPE
        rtype = rng.choice(record_types)
        name = self.random_domain_name(rng)
        ttl = rng.randint(0, 86400)  # 0 to 24 hours
        
        # Generate appropriate rdata based on type
        rdata = None
        if rtype == "A":
            rdata = self.random_ipv4(rng)
        elif rtype == "AAAA":
            rdata = self.random_ipv6(rng)
        elif rtype == "CNAME":
            rdata = self.random_domain_name(rng)
        elif rtype == "MX":
            priority = rng.randint(0, 100)
            exchange = self.random_domain_name(rng)
            rdata = f"{priority} {exchange}"
        elif rtype == "TXT":
            txt_data = self.random_string(rng, rng.randint(1, 50))
            rdata = f'"{txt_data}"'
        elif rtype == "NS":
            rdata = self.random_domain_name(rng)
        elif rtype == "PTR":
            rdata = self.random_domain_name(rng)
        elif rtype == "SOA":
            mname = self.random_domain_name(rng)
            rname = self.random_domain_name(rng)
            serial = rng.randint(1, 2147483647)
            refresh = rng.randint(3600, 86400)
            retry = rng.randint(1800, 7200)
            expire = rng.randint(604800, 2419200)
            minimum = rng.randint(300, 86400)
            rdata = f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
        else:
            rdata = self.random_string(rng)
        
        return {
            'name': name,
            'type': rtype,
            'class': 'IN',
            'ttl': ttl,
            'rdata': rdata
        }

    def generate_random_records(self, rng: random.Random, num_records: int = 1, 
                              record_types: List[str] = None, 
                              use_logical_scenarios: bool = False,
                              scenario_probability: float = 0.3) -> List[dict]:
        """
        Generate multiple random DNS resource records.
        
        Args:
            rng: Random number generator
            num_records: Number of records to generate
            record_types: List of record types to choose from
            use_logical_scenarios: Whether to use logical DNS scenarios
            scenario_probability: Probability of generating a logical scenario
        
        Returns:
            List of DNS resource records
        """
        records = []
        
        # Decide whether to use logical scenarios
        if use_logical_scenarios and rng.random() < scenario_probability:
            try:
                # Import here to avoid circular imports
                from .logical import LogicalRecordGenerator, ScenarioType
                
                logical_gen = LogicalRecordGenerator()
                
                # Choose a random scenario type
                scenario_type = rng.choice(list(ScenarioType))
                
                # Generate logical records based on scenario
                logical_records = logical_gen.generate_logical_records(rng, scenario_type)
                
                # If we got logical records, use them (up to num_records)
                if logical_records:
                    records.extend(logical_records[:num_records])
                    
                    # Fill remaining slots with regular records if needed
                    remaining = num_records - len(records)
                    if remaining > 0:
                        for _ in range(remaining):
                            record = self.generate_random_record(rng, record_types)
                            records.append(record)
                    
                    return records
                    
            except ImportError:
                # Fallback to original logic if logical_records module is not available
                pass
        
        # Original logic with some improvements
        for _ in range(num_records):
            record = self.generate_random_record(rng, record_types)
            
            # Enhanced logic for NS records - always create glue when NS is in same zone
            if record['type'] == "NS":
                ns_name = record['rdata']
                zone_name = record['name']
                
                # Check if NS is within the same zone (needs glue)
                if ns_name.endswith('.' + zone_name) or ns_name == zone_name:
                    # Create glue A record
                    glue_record = {
                        'name': ns_name,
                        'type': "A",
                        'class': 'IN',
                        'ttl': record['ttl'],
                        'rdata': self.random_ipv4(rng)
                    }
                    records.append(glue_record)
                    
                    # Sometimes add AAAA glue record too
                    if rng.choice([True, False]):
                        glue_aaaa_record = {
                            'name': ns_name,
                            'type': "AAAA",
                            'class': 'IN',
                            'ttl': record['ttl'],
                            'rdata': self.random_ipv6(rng)
                        }
                        records.append(glue_aaaa_record)
            
            # Enhanced logic for CNAME records - create target A record
            elif record['type'] == "CNAME":
                target_name = record['rdata']
                
                # Create target A record with some probability
                if rng.choice([True, False]):
                    target_record = {
                        'name': target_name,
                        'type': "A",
                        'class': 'IN',
                        'ttl': record['ttl'],
                        'rdata': self.random_ipv4(rng)
                    }
                    records.append(target_record)
            
            # Enhanced logic for MX records - create target A record
            elif record['type'] == "MX":
                # Extract exchange name from MX rdata (format: "priority exchange")
                parts = record['rdata'].split(' ', 1)
                if len(parts) == 2:
                    exchange_name = parts[1]
                    
                    # Create A record for MX target
                    if rng.choice([True, False]):
                        mx_a_record = {
                            'name': exchange_name,
                            'type': "A",
                            'class': 'IN',
                            'ttl': record['ttl'],
                            'rdata': self.random_ipv4(rng)
                        }
                        records.append(mx_a_record)
            
            records.append(record)
        
        return records

    def mutate_record(self, rng: random.Random, record: dict) -> dict:
        """Mutate a DNS resource record."""
        new_record = record.copy()
        
        # Choose what to mutate
        fields_to_mutate = rng.choices(
            list(constants.DEFAULT_MUTATE_FILEDS.keys()),
            weights=list(constants.DEFAULT_MUTATE_FILEDS.values()),
            k=rng.randint(1, 3)
        )
        
        for field in fields_to_mutate:
            if field == 'name':
                new_record['name'] = self.mutate_string_field(
                    rng, record['name'], ["replace", "append", "prepend"]
                )
            elif field == 'type':
                types = constants.DEFAULT_RECORD_TYPE
                new_record['type'] = rng.choice(types)
            elif field == 'class':
                classes = constants.DEFAULT_CLASS_TYPE
                new_record['class'] = rng.choice(classes)
            elif field == 'ttl':
                new_record['ttl'] = self.mutate_numeric_field(
                    rng, record['ttl'], 0, 2147483647
                )
            elif field == 'rdata':
                # Generate new rdata based on type
                if record['type'] == 'A':
                    new_record['rdata'] = self.random_ipv4(rng)
                elif record['type'] == 'AAAA':
                    new_record['rdata'] = self.random_ipv6(rng)
                else:
                    new_record['rdata'] = self.generate_random_record(rng, [record['type']]).get('rdata', "RADNOM_IS_NONE_RECORD")
        
        return new_record