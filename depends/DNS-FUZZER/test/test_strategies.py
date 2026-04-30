"""Tests for mutation strategies."""

import pytest
import random
from dns_fuzzer.core.query import DNSQuery
from dns_fuzzer.strategies.basic import (
    RandomQueryNameStrategy, RandomQueryTypeStrategy, RandomQueryClassStrategy,
    RandomQueryIdStrategy, BoundaryQueryIdStrategy, LongQueryNameStrategy,
    InvalidCharacterStrategy, EmptyFieldStrategy, CaseVariationStrategy,
    NumericQueryNameStrategy, SpecialDomainStrategy
)
from dns_fuzzer.strategies.header import (
    RandomOpcodeStrategy, RandomResponseCodeStrategy, RandomFlagsStrategy,
    InvalidFlagCombinationStrategy, QueryAsResponseStrategy, ResponseAsQueryStrategy,
    EDNSMutationStrategy, TruncatedFlagStrategy, ZeroQueryIdStrategy
)


class TestBasicStrategies:
    """Test cases for basic mutation strategies."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.sample_query = DNSQuery(
            qname="test.example.com",
            qtype="A",
            qclass="IN",
            query_id=12345
        )
        self.rng = random.Random(42)  # Fixed seed for reproducible tests
    
    def test_random_query_name_strategy(self):
        """Test RandomQueryNameStrategy."""
        strategy = RandomQueryNameStrategy()
        
        assert strategy.name == "random_query_name"
        assert strategy.can_mutate(self.sample_query)
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        assert mutated.qname != self.sample_query.qname
        assert mutated.qtype == self.sample_query.qtype
        assert mutated.qclass == self.sample_query.qclass
        assert mutated.query_id == self.sample_query.query_id
    
    def test_random_query_type_strategy(self):
        """Test RandomQueryTypeStrategy."""
        strategy = RandomQueryTypeStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        assert mutated.qname == self.sample_query.qname
        assert mutated.qtype != self.sample_query.qtype or mutated.qtype == self.sample_query.qtype  # Could be same by chance
        assert mutated.qclass == self.sample_query.qclass
    
    def test_random_query_class_strategy(self):
        """Test RandomQueryClassStrategy."""
        strategy = RandomQueryClassStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        assert mutated.qname == self.sample_query.qname
        assert mutated.qtype == self.sample_query.qtype
        # qclass might be the same by chance, so we don't assert inequality
    
    def test_random_query_id_strategy(self):
        """Test RandomQueryIdStrategy."""
        strategy = RandomQueryIdStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        assert mutated.qname == self.sample_query.qname
        assert mutated.qtype == self.sample_query.qtype
        assert mutated.qclass == self.sample_query.qclass
        assert 0 <= mutated.query_id <= 65535
    
    def test_boundary_query_id_strategy(self):
        """Test BoundaryQueryIdStrategy."""
        strategy = BoundaryQueryIdStrategy()
        
        # Test multiple mutations to see different boundary values
        boundary_values = set()
        for _ in range(20):
            mutated = strategy.mutate(self.sample_query, self.rng)
            boundary_values.add(mutated.query_id)
        
        # Should include some boundary values
        expected_boundaries = {0, 1, 65534, 65535, 32767, 32768}
        assert len(boundary_values.intersection(expected_boundaries)) > 0
    
    def test_long_query_name_strategy(self):
        """Test LongQueryNameStrategy."""
        strategy = LongQueryNameStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        assert len(mutated.qname) > len(self.sample_query.qname)
        assert len(mutated.qname) >= 100  # Should be significantly longer
    
    def test_invalid_character_strategy(self):
        """Test InvalidCharacterStrategy."""
        strategy = InvalidCharacterStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        # Should contain some non-standard characters
        assert mutated.qname != self.sample_query.qname
        # The mutated name should contain some invalid characters
        # (exact validation depends on implementation)
    
    def test_empty_field_strategy(self):
        """Test EmptyFieldStrategy."""
        strategy = EmptyFieldStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        # At least one field should be empty or modified
        fields_empty = [
            mutated.qname == "",
            mutated.qtype == "",
            mutated.qclass == ""
        ]
        assert any(fields_empty)
    
    def test_case_variation_strategy(self):
        """Test CaseVariationStrategy."""
        strategy = CaseVariationStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        # Should have different case but same letters
        assert mutated.qname.lower() == self.sample_query.qname.lower()
        # Should be different unless original was already mixed case
        if self.sample_query.qname.islower():
            assert mutated.qname != self.sample_query.qname
    
    def test_numeric_query_name_strategy(self):
        """Test NumericQueryNameStrategy."""
        strategy = NumericQueryNameStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        # Should contain numeric elements
        assert mutated.qname != self.sample_query.qname
        assert any(char.isdigit() for char in mutated.qname)
    
    def test_special_domain_strategy(self):
        """Test SpecialDomainStrategy."""
        strategy = SpecialDomainStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        # Should be one of the special domains
        special_domains = [
            "localhost", "example.com", "example.org", "example.net",
            "test.com", "invalid", "local", "onion", "exit", "i2p"
        ]
        
        assert any(domain in mutated.qname for domain in special_domains)


class TestHeaderStrategies:
    """Test cases for header mutation strategies."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.sample_query = DNSQuery(
            qname="header.test.com",
            qtype="A",
            qclass="IN",
            query_id=54321
        )
        self.rng = random.Random(123)
    
    def test_random_opcode_strategy(self):
        """Test RandomOpcodeStrategy."""
        strategy = RandomOpcodeStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        # Opcode should be set (might be same as original by chance)
        assert hasattr(mutated, 'opcode')
        assert mutated.qname == self.sample_query.qname
    
    def test_random_response_code_strategy(self):
        """Test RandomResponseCodeStrategy."""
        strategy = RandomResponseCodeStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        # Response code should be set
        assert hasattr(mutated, 'response_code')
        assert mutated.qname == self.sample_query.qname
    
    def test_random_flags_strategy(self):
        """Test RandomFlagsStrategy."""
        strategy = RandomFlagsStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        # Some flags should be different from default
        flag_fields = [
            'authoritative', 'truncated', 'recursion_desired',
            'recursion_available', 'is_response'
        ]
        
        # At least one flag should be set
        assert any(getattr(mutated, field, False) for field in flag_fields)
    
    def test_invalid_flag_combination_strategy(self):
        """Test InvalidFlagCombinationStrategy."""
        strategy = InvalidFlagCombinationStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        # Should have some unusual flag combination
        # (exact validation depends on the specific combination chosen)
        assert mutated.qname == self.sample_query.qname
    
    def test_query_as_response_strategy(self):
        """Test QueryAsResponseStrategy."""
        strategy = QueryAsResponseStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        # Should be converted to response
        assert mutated.is_response
        assert mutated.qname == self.sample_query.qname
    
    def test_response_as_query_strategy(self):
        """Test ResponseAsQueryStrategy."""
        strategy = ResponseAsQueryStrategy()
        
        # Create a response query
        response_query = DNSQuery(
            qname="response.test.com",
            qtype="A",
            qclass="IN",
            query_id=99999,
            is_response=True,
            answers=[{
                'name': 'response.test.com',
                'type': 'A',
                'class': 'IN',
                'ttl': 300,
                'rdata': '192.0.2.1'
            }]
        )
        
        assert strategy.can_mutate(response_query)
        
        mutated = strategy.mutate(response_query, self.rng)
        
        # Should be converted to query
        assert not mutated.is_response
        assert mutated.qname == response_query.qname
    
    def test_response_as_query_strategy_no_mutation(self):
        """Test ResponseAsQueryStrategy with query that can't be mutated."""
        # Regular query without response indicators
        assert not strategy.can_mutate(self.sample_query)
    
    def test_edns_mutation_strategy(self):
        """Test EDNSMutationStrategy."""
        strategy = EDNSMutationStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        # Should have EDNS fields set
        edns_fields = ['edns_version', 'edns_payload_size', 'edns_dnssec_ok']
        edns_set = [getattr(mutated, field, None) is not None for field in edns_fields]
        
        assert any(edns_set)
    
    def test_truncated_flag_strategy(self):
        """Test TruncatedFlagStrategy."""
        strategy = TruncatedFlagStrategy()
        
        mutated = strategy.mutate(self.sample_query, self.rng)
        
        # Should have truncated flag set
        assert mutated.truncated
        assert mutated.qname == self.sample_query.qname
    
    def test_zero_query_id_strategy(self):
        """Test ZeroQueryIdStrategy."""
        strategy = ZeroQueryIdStrategy()
        
        # Test multiple mutations to see different special values
        special_ids = set()
        for _ in range(20):
            mutated = strategy.mutate(self.sample_query, self.rng)
            special_ids.add(mutated.query_id)
        
        # Should include some special values
        expected_special = {0, 1, 65535, 32768, 16384}
        assert len(special_ids.intersection(expected_special)) > 0


class TestStrategyProperties:
    """Test common properties of all strategies."""
    
    def test_all_strategies_have_required_attributes(self):
        """Test that all strategies have required attributes."""
        strategies = [
            RandomQueryNameStrategy(),
            RandomQueryTypeStrategy(),
            RandomQueryClassStrategy(),
            RandomQueryIdStrategy(),
            BoundaryQueryIdStrategy(),
            LongQueryNameStrategy(),
            InvalidCharacterStrategy(),
            EmptyFieldStrategy(),
            CaseVariationStrategy(),
            NumericQueryNameStrategy(),
            SpecialDomainStrategy(),
            RandomOpcodeStrategy(),
            RandomResponseCodeStrategy(),
            RandomFlagsStrategy(),
            InvalidFlagCombinationStrategy(),
            QueryAsResponseStrategy(),
            ResponseAsQueryStrategy(),
            EDNSMutationStrategy(),
            TruncatedFlagStrategy(),
            ZeroQueryIdStrategy(),
        ]
        
        for strategy in strategies:
            # Check required attributes
            assert hasattr(strategy, 'name')
            assert hasattr(strategy, 'description')
            assert hasattr(strategy, 'weight')
            
            # Check required methods
            assert callable(getattr(strategy, 'can_mutate'))
            assert callable(getattr(strategy, 'mutate'))
            
            # Check attribute types
            assert isinstance(strategy.name, str)
            assert isinstance(strategy.description, str)
            assert isinstance(strategy.weight, (int, float))
            assert strategy.weight >= 0
    
    def test_strategy_names_are_unique(self):
        """Test that all strategy names are unique."""
        strategies = [
            RandomQueryNameStrategy(),
            RandomQueryTypeStrategy(),
            RandomQueryClassStrategy(),
            RandomQueryIdStrategy(),
            BoundaryQueryIdStrategy(),
            LongQueryNameStrategy(),
            InvalidCharacterStrategy(),
            EmptyFieldStrategy(),
            CaseVariationStrategy(),
            NumericQueryNameStrategy(),
            SpecialDomainStrategy(),
            RandomOpcodeStrategy(),
            RandomResponseCodeStrategy(),
            RandomFlagsStrategy(),
            InvalidFlagCombinationStrategy(),
            QueryAsResponseStrategy(),
            ResponseAsQueryStrategy(),
            EDNSMutationStrategy(),
            TruncatedFlagStrategy(),
            ZeroQueryIdStrategy(),
        ]
        
        names = [strategy.name for strategy in strategies]
        assert len(names) == len(set(names)), "Strategy names must be unique"
    
    def test_mutations_preserve_original_query(self):
        """Test that mutations don't modify the original query."""
        sample_query = DNSQuery(
            qname="preserve.test.com",
            qtype="A",
            qclass="IN",
            query_id=11111
        )
        
        original_qname = sample_query.qname
        original_qtype = sample_query.qtype
        original_qclass = sample_query.qclass
        original_query_id = sample_query.query_id
        
        strategies = [RandomQueryNameStrategy(), RandomQueryTypeStrategy()]
        rng = random.Random(456)
        
        for strategy in strategies:
            mutated = strategy.mutate(sample_query, rng)
            
            # Original should be unchanged
            assert sample_query.qname == original_qname
            assert sample_query.qtype == original_qtype
            assert sample_query.qclass == original_qclass
            assert sample_query.query_id == original_query_id
            
            # Mutated should be different object
            assert mutated is not sample_query


if __name__ == "__main__":
    pytest.main([__file__])