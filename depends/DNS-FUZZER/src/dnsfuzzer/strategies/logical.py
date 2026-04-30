"""
Logical DNS Record Mutation Strategies.
"""

import random
from typing import List, override
from .base import BaseMutationStrategy
from .logical_record import LogicalRecordGenerator, ScenarioType
from ..core.query import DNSQuery


class LogicalRecordStrategy(BaseMutationStrategy):
    """
    Mutation strategy that generates logically related DNS records.
    """
    
    def __init__(self, scenario_type: ScenarioType = None, **kwargs):
        super().__init__(
            name="logical_record",
            description="Generate logically related DNS records for realistic scenarios",
            **kwargs
        )
        self.scenario_type = scenario_type
        self.logical_gen = LogicalRecordGenerator()
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        """
        Mutate the query by adding logically related records to the additional section.
        """
        # Choose scenario type if not specified
        scenario_type = self.scenario_type
        if scenario_type is None:
            scenario_type = rng.choice(list(ScenarioType))
        
        # Generate logical records
        logical_records = self.logical_gen.generate_logical_records(
            rng, scenario_type, **kwargs
        )
        
        # Convert our record format to DNS records and add to query
        for record_dict in logical_records:
            try:
                # Create DNS record from our dictionary format
                if record_dict:
                    query.additional_records.append(record_dict)
            except Exception:
                # Skip invalid records
                continue
        
        return query


class NSGlueStrategy(LogicalRecordStrategy):
    """Strategy specifically for NS records with glue records."""
    
    def __init__(self, **kwargs):
        super().__init__(
            scenario_type=ScenarioType.NS_WITH_GLUE,
            **kwargs
        )
        self.name = "ns_glue"
        self.description = "Generate NS records with corresponding glue records"
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to responses or packets that can be converted to responses."""
        return query.is_response or bool(query.answers or query.authorities or query.additional)


class CNAMEChainStrategy(LogicalRecordStrategy):
    """Strategy for CNAME chain scenarios."""
    
    def __init__(self, create_loop: bool = False, **kwargs):
        scenario_type = ScenarioType.CNAME_LOOP if create_loop else ScenarioType.CNAME_CHAIN
        super().__init__(scenario_type=scenario_type, **kwargs)
        self.name = "cname_chain"
        self.description = f"Generate CNAME {'loops' if create_loop else 'chains'}"
        self.create_loop = create_loop
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to responses or packets that can be converted to responses."""
        return query.is_response or bool(query.answers or query.authorities or query.additional)
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        """Generate CNAME chain with specified parameters."""
        chain_length = kwargs.get('chain_length', rng.randint(2, 5))
        
        logical_records = self.logical_gen.generate_cname_chain_scenario(
            rng, 
            chain_length=chain_length,
            create_loop=self.create_loop
        )
        
        # Add records to query
        for record_dict in logical_records:
            try:
                if record_dict:
                    query.additional_records.append(record_dict)
            except Exception:
                continue
        
        return query


class ZoneStructureStrategy(LogicalRecordStrategy):
    """Strategy for complete zone structure scenarios."""
    
    def __init__(self, **kwargs):
        super().__init__(
            scenario_type=ScenarioType.ZONE_STRUCTURE,
            **kwargs
        )
        self.name = "zone_structure"
        self.description = "Generate complete DNS zone structures with SOA, NS, and various records"
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to responses or packets that can be converted to responses."""
        return query.is_response or bool(query.answers or query.authorities or query.additional)


class AuthorityAdditionalStrategy(LogicalRecordStrategy):
    """Strategy for authority and additional record relationships."""
    
    def __init__(self, **kwargs):
        super().__init__(
            scenario_type=ScenarioType.AUTHORITY_ADDITIONAL,
            **kwargs
        )
        self.name = "authority_additional"
        self.description = "Generate authority and additional records with logical relationships"
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to responses or packets that can be converted to responses."""
        return query.is_response or bool(query.answers or query.authorities or query.additional)
    
    @override
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        """Generate authority and additional records."""
        query_name = kwargs.get('query_name', query.qname)
        
        answer_records, authority_records, additional_records = \
            self.logical_gen.generate_authority_additional_scenario(rng, query_name)
        
        # Add records to appropriate sections
        for record_dict in answer_records:
            try:
                if record_dict:
                    query.answer_records.append(record_dict)
            except Exception:
                continue
        
        for record_dict in authority_records:
            try:
                if record_dict:
                    query.authority_records.append(record_dict)
            except Exception:
                continue
        
        for record_dict in additional_records:
            try:
                if record_dict:
                    query.additional_records.append(record_dict)
            except Exception:
                continue
        
        return query


class LogicalWildcardRecordStrategy(LogicalRecordStrategy):
    """Strategy for wildcard DNS record scenarios."""
    
    def __init__(self, **kwargs):
        super().__init__(
            scenario_type=ScenarioType.WILDCARD_RECORDS,
            **kwargs
        )
        self.name = "logical_wildcard_record"
        self.description = "Generate wildcard DNS records with specific overrides"
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """This strategy applies to responses or packets that can be converted to responses."""
        return query.is_response or bool(query.answers or query.authorities or query.additional)


# Convenience function to get all logical strategies
def get_logical_strategies() -> List[BaseMutationStrategy]:
    """
    Get all available logical record mutation strategies.
    
    Returns:
        List of logical mutation strategy instances
    """
    return [
        LogicalRecordStrategy(),
        NSGlueStrategy(),
        CNAMEChainStrategy(),
        CNAMEChainStrategy(create_loop=True),
        ZoneStructureStrategy(),
        AuthorityAdditionalStrategy(),
        LogicalWildcardRecordStrategy(),
    ]


# Strategy weights for different scenarios (can be used in configuration)
LOGICAL_STRATEGY_WEIGHTS = {
    "logical_record": 1.0,
    "ns_glue": 0.8,
    "cname_chain": 0.7,
    "zone_structure": 0.5,
    "authority_additional": 0.9,
    "logical_wildcard_record": 0.4,
}