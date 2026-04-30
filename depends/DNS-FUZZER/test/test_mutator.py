"""Tests for DNS mutator module."""

import pytest
import random
from unittest.mock import Mock, patch
from dns_fuzzer.core.query import DNSQuery
from dns_fuzzer.core.mutator import DNSMutator, MutationStrategy


class MockStrategy(MutationStrategy):
    """Mock strategy for testing."""
    
    def __init__(self, name: str, weight: float = 1.0, should_mutate: bool = True):
        self.name = name
        self.description = f"Mock strategy {name}"
        self.weight = weight
        self._should_mutate = should_mutate
        self.mutation_count = 0
    
    def can_mutate(self, query: DNSQuery) -> bool:
        return self._should_mutate
    
    def mutate(self, query: DNSQuery, rng: random.Random) -> DNSQuery:
        self.mutation_count += 1
        mutated = query.clone()
        mutated.qname = f"mutated-{self.name}-{mutated.qname}"
        return mutated


class TestDNSMutator:
    """Test cases for DNSMutator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mutator = DNSMutator()
        self.sample_query = DNSQuery(
            qname="test.example.com",
            qtype="A",
            qclass="IN",
            query_id=12345
        )
    
    def test_register_strategy(self):
        """Test registering a mutation strategy."""
        strategy = MockStrategy("test_strategy")
        
        self.mutator.register_strategy(strategy)
        
        assert "test_strategy" in self.mutator.list_strategies()
        assert self.mutator.get_strategy("test_strategy") is strategy
    
    def test_register_duplicate_strategy(self):
        """Test registering a strategy with duplicate name."""
        strategy1 = MockStrategy("duplicate")
        strategy2 = MockStrategy("duplicate")
        
        self.mutator.register_strategy(strategy1)
        self.mutator.register_strategy(strategy2)
        
        # Should replace the first strategy
        assert self.mutator.get_strategy("duplicate") is strategy2
    
    def test_unregister_strategy(self):
        """Test unregistering a mutation strategy."""
        strategy = MockStrategy("to_remove")
        
        self.mutator.register_strategy(strategy)
        assert "to_remove" in self.mutator.list_strategies()
        
        result = self.mutator.unregister_strategy("to_remove")
        assert result is True
        assert "to_remove" not in self.mutator.list_strategies()
        
        # Try to remove non-existent strategy
        result = self.mutator.unregister_strategy("non_existent")
        assert result is False
    
    def test_get_nonexistent_strategy(self):
        """Test getting a non-existent strategy."""
        result = self.mutator.get_strategy("non_existent")
        assert result is None
    
    def test_mutate_with_specific_strategy(self):
        """Test mutating with a specific strategy."""
        strategy = MockStrategy("specific")
        self.mutator.register_strategy(strategy)
        
        mutated = self.mutator.mutate(self.sample_query, strategy_name="specific")
        
        assert mutated.qname == "mutated-specific-test.example.com"
        assert strategy.mutation_count == 1
    
    def test_mutate_with_nonexistent_strategy(self):
        """Test mutating with a non-existent strategy."""
        with pytest.raises(ValueError, match="Strategy 'non_existent' not found"):
            self.mutator.mutate(self.sample_query, strategy_name="non_existent")
    
    def test_mutate_random_strategy(self):
        """Test mutating with random strategy selection."""
        strategy1 = MockStrategy("random1", weight=1.0)
        strategy2 = MockStrategy("random2", weight=2.0)
        
        self.mutator.register_strategy(strategy1)
        self.mutator.register_strategy(strategy2)
        
        # Set seed for reproducible results
        mutated = self.mutator.mutate(self.sample_query, seed=42)
        
        # Should be mutated by one of the strategies
        assert mutated.qname.startswith("mutated-")
        assert (strategy1.mutation_count + strategy2.mutation_count) == 1
    
    def test_mutate_no_strategies(self):
        """Test mutating when no strategies are registered."""
        with pytest.raises(ValueError, match="No mutation strategies registered"):
            self.mutator.mutate(self.sample_query)
    
    def test_mutate_no_applicable_strategies(self):
        """Test mutating when no strategies can mutate the query."""
        strategy = MockStrategy("inapplicable", should_mutate=False)
        self.mutator.register_strategy(strategy)
        
        with pytest.raises(ValueError, match="No applicable strategies found"):
            self.mutator.mutate(self.sample_query)
    
    def test_mutate_batch(self):
        """Test batch mutation."""
        strategy = MockStrategy("batch")
        self.mutator.register_strategy(strategy)
        
        queries = [
            DNSQuery(qname="query1.com", qtype="A", qclass="IN"),
            DNSQuery(qname="query2.com", qtype="A", qclass="IN"),
            DNSQuery(qname="query3.com", qtype="A", qclass="IN"),
        ]
        
        mutated_queries = self.mutator.mutate_batch(queries, seed=123)
        
        assert len(mutated_queries) == 3
        assert all(q.qname.startswith("mutated-batch-") for q in mutated_queries)
        assert strategy.mutation_count == 3
    
    def test_mutate_batch_with_strategy(self):
        """Test batch mutation with specific strategy."""
        strategy1 = MockStrategy("batch1")
        strategy2 = MockStrategy("batch2")
        
        self.mutator.register_strategy(strategy1)
        self.mutator.register_strategy(strategy2)
        
        queries = [
            DNSQuery(qname="query1.com", qtype="A", qclass="IN"),
            DNSQuery(qname="query2.com", qtype="A", qclass="IN"),
        ]
        
        mutated_queries = self.mutator.mutate_batch(
            queries, 
            strategy_name="batch1"
        )
        
        assert len(mutated_queries) == 2
        assert all(q.qname.startswith("mutated-batch1-") for q in mutated_queries)
        assert strategy1.mutation_count == 2
        assert strategy2.mutation_count == 0
    
    def test_mutation_history(self):
        """Test mutation history tracking."""
        strategy = MockStrategy("history")
        self.mutator.register_strategy(strategy)
        
        # Perform some mutations
        self.mutator.mutate(self.sample_query, strategy_name="history")
        self.mutator.mutate(self.sample_query, strategy_name="history")
        
        history = self.mutator.get_mutation_history()
        
        assert len(history) == 2
        assert all(entry["strategy"] == "history" for entry in history)
        assert all("timestamp" in entry for entry in history)
    
    def test_clear_history(self):
        """Test clearing mutation history."""
        strategy = MockStrategy("clear_test")
        self.mutator.register_strategy(strategy)
        
        self.mutator.mutate(self.sample_query, strategy_name="clear_test")
        assert len(self.mutator.get_mutation_history()) == 1
        
        self.mutator.clear_history()
        assert len(self.mutator.get_mutation_history()) == 0
    
    def test_get_statistics(self):
        """Test getting mutation statistics."""
        strategy1 = MockStrategy("stats1")
        strategy2 = MockStrategy("stats2")
        
        self.mutator.register_strategy(strategy1)
        self.mutator.register_strategy(strategy2)
        
        # Perform mutations
        self.mutator.mutate(self.sample_query, strategy_name="stats1")
        self.mutator.mutate(self.sample_query, strategy_name="stats1")
        self.mutator.mutate(self.sample_query, strategy_name="stats2")
        
        stats = self.mutator.get_statistics()
        
        assert stats["total_mutations"] == 3
        assert stats["strategy_usage"]["stats1"] == 2
        assert stats["strategy_usage"]["stats2"] == 1
    
    def test_create_strategy_chain(self):
        """Test creating a strategy chain."""
        strategy1 = MockStrategy("chain1")
        strategy2 = MockStrategy("chain2")
        
        self.mutator.register_strategy(strategy1)
        self.mutator.register_strategy(strategy2)
        
        chain = self.mutator.create_strategy_chain(["chain1", "chain2"])
        
        # Apply the chain
        result = self.sample_query
        for strategy_func in chain:
            result = strategy_func(result)
        
        # Should be mutated by both strategies
        assert "mutated-chain1-" in result.qname
        assert "mutated-chain2-" in result.qname
    
    def test_create_strategy_chain_invalid(self):
        """Test creating a strategy chain with invalid strategy."""
        with pytest.raises(ValueError, match="Strategy 'invalid' not found"):
            self.mutator.create_strategy_chain(["invalid"])
    
    @patch('dns_fuzzer.core.mutator.importlib.import_module')
    def test_load_strategy_from_module(self, mock_import):
        """Test loading strategy from module."""
        # Mock the module and strategy class
        mock_strategy_class = Mock()
        mock_strategy_instance = MockStrategy("loaded")
        mock_strategy_class.return_value = mock_strategy_instance
        
        mock_module = Mock()
        mock_module.TestStrategy = mock_strategy_class
        mock_import.return_value = mock_module
        
        self.mutator.load_strategy_from_module("test_module", "TestStrategy")
        
        assert "loaded" in self.mutator.list_strategies()
        mock_import.assert_called_once_with("test_module")
    
    @patch('dns_fuzzer.core.mutator.importlib.import_module')
    def test_load_strategy_from_module_error(self, mock_import):
        """Test loading strategy from module with error."""
        mock_import.side_effect = ImportError("Module not found")
        
        with pytest.raises(ImportError):
            self.mutator.load_strategy_from_module("invalid_module", "TestStrategy")
    
    def test_weighted_strategy_selection(self):
        """Test that strategy selection respects weights."""
        # Create strategies with different weights
        strategy_low = MockStrategy("low_weight", weight=0.1)
        strategy_high = MockStrategy("high_weight", weight=10.0)
        
        self.mutator.register_strategy(strategy_low)
        self.mutator.register_strategy(strategy_high)
        
        # Run multiple mutations and check distribution
        high_count = 0
        low_count = 0
        
        for i in range(100):
            mutated = self.mutator.mutate(self.sample_query, seed=i)
            if "high_weight" in mutated.qname:
                high_count += 1
            elif "low_weight" in mutated.qname:
                low_count += 1
        
        # High weight strategy should be selected more often
        assert high_count > low_count
        assert high_count > 50  # Should be significantly more


if __name__ == "__main__":
    pytest.main([__file__])