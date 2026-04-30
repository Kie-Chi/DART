"""
Logical DNS Record Generator for creating realistic DNS scenarios.

"""

import random
from typing import List, Dict, Tuple
from dataclasses import dataclass
from enum import Enum


class ScenarioType(Enum):
    """DNS scenario types for logical record generation."""
    NS_WITH_GLUE = "ns_with_glue"
    CNAME_CHAIN = "cname_chain"
    CNAME_LOOP = "cname_loop"
    AUTHORITY_ADDITIONAL = "authority_additional"
    ZONE_STRUCTURE = "zone_structure"
    DELEGATION = "delegation"
    WILDCARD_RECORDS = "wildcard_records"


@dataclass
class DNSZone:
    """Represents a DNS zone structure."""
    name: str
    soa_record: Dict
    ns_records: List[Dict]
    glue_records: List[Dict]
    other_records: List[Dict]


class LogicalRecordGenerator:
    """
    Advanced DNS record generator that creates logically related records
    simulating real-world DNS scenarios.
    """
    
    def __init__(self):
        self.zones: Dict[str, DNSZone] = {}
        self.cname_chains: List[List[str]] = []
        
    def random_string(self, rng: random.Random, length: int = None, 
                     charset: str = "abcdefghijklmnopqrstuvwxyz0123456789") -> str:
        """Generate a random string."""
        if length is None:
            length = rng.randint(3, 10)
        return ''.join(rng.choice(charset) for _ in range(length))
    
    def random_domain_name(self, rng: random.Random, max_labels: int = 3, 
                          base_domain: str = None) -> str:
        """Generate a random domain name, optionally based on a base domain."""
        if base_domain:
            subdomain = self.random_string(rng, rng.randint(3, 8))
            domain = f"{subdomain}.{base_domain}"
        else:
            labels = []
            for _ in range(rng.randint(1, max_labels)):
                labels.append(self.random_string(rng, rng.randint(3, 8)))
            
            # Add a realistic TLD
            tlds = ["com", "org", "net", "edu", "gov", "mil", "int"]
            labels.append(rng.choice(tlds))
            
            domain = '.'.join(labels)
        
        # Ensure domain name is absolute (ends with dot)
        if not domain.endswith('.'):
            domain += '.'
        return domain
    
    def random_ipv4(self, rng: random.Random) -> str:
        """Generate a random IPv4 address."""
        return '.'.join(str(rng.randint(1, 254)) for _ in range(4))
    
    def random_ipv6(self, rng: random.Random) -> str:
        """Generate a random IPv6 address."""
        groups = []
        for _ in range(8):
            groups.append(f"{rng.randint(0, 65535):04x}")
        return ':'.join(groups)
    
    def generate_ns_with_glue_scenario(self, rng: random.Random, 
                                     zone_name: str = None) -> List[Dict]:
        """
        Generate NS records with corresponding glue records.
        
        This simulates the scenario where a zone delegates to nameservers
        within the same zone, requiring glue records.
        """
        if zone_name is None:
            zone_name = self.random_domain_name(rng, max_labels=2)
        
        records = []
        ns_count = rng.randint(2, 4)  # Typical number of nameservers
        
        for i in range(ns_count):
            # Create NS record pointing to a nameserver within the zone
            ns_name = f"ns{i+1}.{zone_name}"
            ns_record = {
                'name': zone_name,
                'type': 'NS',
                'class': 'IN',
                'ttl': rng.randint(3600, 86400),
                'rdata': ns_name
            }
            records.append(ns_record)
            
            # Create corresponding glue A record
            glue_a_record = {
                'name': ns_name,
                'type': 'A',
                'class': 'IN',
                'ttl': rng.randint(3600, 86400),
                'rdata': self.random_ipv4(rng)
            }
            records.append(glue_a_record)
            
            # Sometimes add AAAA glue record too
            if rng.choice([True, False]):
                glue_aaaa_record = {
                    'name': ns_name,
                    'type': 'AAAA',
                    'class': 'IN',
                    'ttl': rng.randint(3600, 86400),
                    'rdata': self.random_ipv6(rng)
                }
                records.append(glue_aaaa_record)
        
        return records
    
    def generate_cname_chain_scenario(self, rng: random.Random, 
                                    chain_length: int = None,
                                    create_loop: bool = False) -> List[Dict]:
        """
        Generate a CNAME chain scenario.
        
        Args:
            chain_length: Length of the CNAME chain (2-5 if None)
            create_loop: Whether to create a CNAME loop (for testing)
        """
        if chain_length is None:
            chain_length = rng.randint(2, 5)
        
        records = []
        domains = []
        
        # Generate domain names for the chain
        for i in range(chain_length):
            if i == 0:
                # First domain is the original query target
                domain = f"alias{i+1}.{self.random_domain_name(rng, max_labels=2)}"
            else:
                domain = f"target{i}.{self.random_domain_name(rng, max_labels=2)}"
            domains.append(domain)
        
        # Create CNAME records
        for i in range(len(domains) - 1):
            target = domains[0] if create_loop and i == len(domains) - 2 else domains[i + 1]
            cname_record = {
                'name': domains[i],
                'type': 'CNAME',
                'class': 'IN',
                'ttl': rng.randint(300, 3600),
                'rdata': target
            }
            records.append(cname_record)
        
        # Add final A record (unless it's a loop)
        if not create_loop:
            final_a_record = {
                'name': domains[-1],
                'type': 'A',
                'class': 'IN',
                'ttl': rng.randint(300, 3600),
                'rdata': self.random_ipv4(rng)
            }
            records.append(final_a_record)
        
        return records
    
    def generate_authority_additional_scenario(self, rng: random.Random,
                                             query_name: str = None) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """
        Generate authority and additional records for a DNS response.
        
        Returns:
            Tuple of (answer_records, authority_records, additional_records)
        """
        if query_name is None:
            query_name = self.random_domain_name(rng)
        
        # Extract zone from query name
        labels = query_name.split('.')
        if len(labels) >= 2:
            zone_name = '.'.join(labels[-2:])  # Take last two labels as zone
        else:
            zone_name = query_name
        
        answer_records = []
        authority_records = []
        additional_records = []
        
        # Generate answer record
        answer_record = {
            'name': query_name,
            'type': 'A',
            'class': 'IN',
            'ttl': rng.randint(300, 3600),
            'rdata': self.random_ipv4(rng)
        }
        answer_records.append(answer_record)
        
        # Generate authority records (NS records for the zone)
        ns_names = []
        for i in range(rng.randint(2, 4)):
            ns_name = f"ns{i+1}.{zone_name}"
            ns_names.append(ns_name)
            
            ns_record = {
                'name': zone_name,
                'type': 'NS',
                'class': 'IN',
                'ttl': rng.randint(3600, 86400),
                'rdata': ns_name
            }
            authority_records.append(ns_record)
        
        # Generate additional records (A records for NS servers)
        for ns_name in ns_names:
            additional_record = {
                'name': ns_name,
                'type': 'A',
                'class': 'IN',
                'ttl': rng.randint(3600, 86400),
                'rdata': self.random_ipv4(rng)
            }
            additional_records.append(additional_record)
            
            # Sometimes add AAAA record too
            if rng.choice([True, False]):
                additional_aaaa_record = {
                    'name': ns_name,
                    'type': 'AAAA',
                    'class': 'IN',
                    'ttl': rng.randint(3600, 86400),
                    'rdata': self.random_ipv6(rng)
                }
                additional_records.append(additional_aaaa_record)
        
        return answer_records, authority_records, additional_records
    
    def generate_zone_structure_scenario(self, rng: random.Random,
                                       zone_name: str = None) -> List[Dict]:
        """
        Generate a complete zone structure with SOA, NS, and various records.
        """
        if zone_name is None:
            zone_name = self.random_domain_name(rng, max_labels=2)
        
        records = []
        
        # Generate SOA record
        primary_ns = f"ns1.{zone_name}"
        admin_email = f"admin.{zone_name}"
        serial = rng.randint(2020010101, 2024123199)
        refresh = rng.choice([3600, 7200, 14400, 28800])
        retry = rng.choice([1800, 3600, 7200])
        expire = rng.choice([604800, 1209600, 2419200])
        minimum = rng.choice([300, 600, 3600])
        
        soa_record = {
            'name': zone_name,
            'type': 'SOA',
            'class': 'IN',
            'ttl': rng.randint(3600, 86400),
            'rdata': f"{primary_ns} {admin_email} {serial} {refresh} {retry} {expire} {minimum}"
        }
        records.append(soa_record)
        
        # Generate NS records with glue
        ns_records = self.generate_ns_with_glue_scenario(rng, zone_name)
        records.extend(ns_records)
        
        # Generate some A records for the zone
        for i in range(rng.randint(3, 8)):
            if i == 0:
                # Apex A record
                name = zone_name
            else:
                # Subdomain A records
                subdomain = self.random_string(rng, rng.randint(3, 10))
                name = f"{subdomain}.{zone_name}"
            
            a_record = {
                'name': name,
                'type': 'A',
                'class': 'IN',
                'ttl': rng.randint(300, 3600),
                'rdata': self.random_ipv4(rng)
            }
            records.append(a_record)
        
        # Generate some MX records
        for i in range(rng.randint(1, 3)):
            priority = (i + 1) * 10
            mx_name = f"mail{i+1}.{zone_name}"
            
            mx_record = {
                'name': zone_name,
                'type': 'MX',
                'class': 'IN',
                'ttl': rng.randint(3600, 86400),
                'rdata': f"{priority} {mx_name}"
            }
            records.append(mx_record)
            
            # Add A record for MX target
            mx_a_record = {
                'name': mx_name,
                'type': 'A',
                'class': 'IN',
                'ttl': rng.randint(300, 3600),
                'rdata': self.random_ipv4(rng)
            }
            records.append(mx_a_record)
        
        return records
    
    def generate_wildcard_scenario(self, rng: random.Random,
                                 zone_name: str = None) -> List[Dict]:
        """
        Generate wildcard DNS records scenario.
        """
        if zone_name is None:
            zone_name = self.random_domain_name(rng, max_labels=2)
        
        records = []
        
        # Generate wildcard A record
        wildcard_record = {
            'name': f"*.{zone_name}",
            'type': 'A',
            'class': 'IN',
            'ttl': rng.randint(300, 3600),
            'rdata': self.random_ipv4(rng)
        }
        records.append(wildcard_record)
        
        # Generate some specific records that would override the wildcard
        for subdomain in ['www', 'mail', 'ftp']:
            specific_record = {
                'name': f"{subdomain}.{zone_name}",
                'type': 'A',
                'class': 'IN',
                'ttl': rng.randint(300, 3600),
                'rdata': self.random_ipv4(rng)
            }
            records.append(specific_record)
        
        return records
    
    def generate_logical_records(self, rng: random.Random, 
                               scenario_type: ScenarioType = None,
                               **kwargs) -> List[Dict]:
        """
        Generate logically related DNS records based on the specified scenario.
        
        Args:
            scenario_type: Type of DNS scenario to generate
            **kwargs: Additional parameters for specific scenarios
        """
        if scenario_type is None:
            scenario_type = rng.choice(list(ScenarioType))
        
        if scenario_type == ScenarioType.NS_WITH_GLUE:
            return self.generate_ns_with_glue_scenario(rng, **kwargs)
        elif scenario_type == ScenarioType.CNAME_CHAIN:
            return self.generate_cname_chain_scenario(rng, **kwargs)
        elif scenario_type == ScenarioType.CNAME_LOOP:
            return self.generate_cname_chain_scenario(rng, create_loop=True, **kwargs)
        elif scenario_type == ScenarioType.AUTHORITY_ADDITIONAL:
            answer, authority, additional = self.generate_authority_additional_scenario(rng, **kwargs)
            return answer + authority + additional
        elif scenario_type == ScenarioType.ZONE_STRUCTURE:
            return self.generate_zone_structure_scenario(rng, **kwargs)
        elif scenario_type == ScenarioType.WILDCARD_RECORDS:
            return self.generate_wildcard_scenario(rng, **kwargs)
        else:
            # Fallback to NS with glue
            return self.generate_ns_with_glue_scenario(rng, **kwargs)