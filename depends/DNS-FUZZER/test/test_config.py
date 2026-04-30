"""Tests for configuration module."""

import pytest
import tempfile
import os
from pathlib import Path
from dnsfuzzer.config import FuzzerConfig, StrategyConfig, create_default_config, load_config


class TestStrategyConfig:
    """Test cases for StrategyConfig class."""
    
    def test_create_strategy_config(self):
        """Test creating a strategy configuration."""
        config = StrategyConfig(
            name="test_strategy",
            enabled=True,
            weight=1.5,
            parameters={"param1": "value1"}
        )
        
        assert config.name == "test_strategy"
        assert config.enabled is True
        assert config.weight == 1.5
        assert config.parameters == {"param1": "value1"}
    
    def test_strategy_config_defaults(self):
        """Test strategy configuration with default values."""
        config = StrategyConfig(name="default_test")
        
        assert config.name == "default_test"
        assert config.enabled is True
        assert config.weight == 1.0
        assert config.parameters == {}


class TestFuzzerConfig:
    """Test cases for FuzzerConfig class."""
    
    def test_create_default_config(self):
        """Test creating a default fuzzer configuration."""
        config = FuzzerConfig()
        
        assert config.target_servers == ["8.8.8.8", "1.1.1.1"]
        assert config.target_port == 53
        assert config.timeout == 5.0
        assert config.max_iterations == 1000
        assert config.concurrent_requests == 10
        assert config.delay_between_requests == 0.1
        assert config.strategies == []
        assert config.strategy_selection_mode == "weighted_random"
        assert config.output_directory == "fuzzer_output"
        assert config.log_level == "INFO"
        assert config.save_packets is True
        assert config.save_responses is True
        assert config.default_query_name == "example.com"
        assert config.default_query_type == "A"
        assert config.default_query_class == "IN"
        assert config.random_seed is None
    
    def test_add_strategy(self):
        """Test adding a strategy to configuration."""
        config = FuzzerConfig()
        
        config.add_strategy("test_strategy", enabled=True, weight=2.0, 
                          parameters={"test": "value"})
        
        assert len(config.strategies) == 1
        strategy = config.strategies[0]
        assert strategy.name == "test_strategy"
        assert strategy.enabled is True
        assert strategy.weight == 2.0
        assert strategy.parameters == {"test": "value"}
    
    def test_add_existing_strategy(self):
        """Test adding a strategy that already exists (should update)."""
        config = FuzzerConfig()
        
        config.add_strategy("existing", weight=1.0)
        config.add_strategy("existing", weight=2.0, enabled=False)
        
        assert len(config.strategies) == 1
        strategy = config.strategies[0]
        assert strategy.name == "existing"
        assert strategy.weight == 2.0
        assert strategy.enabled is False
    
    def test_remove_strategy(self):
        """Test removing a strategy from configuration."""
        config = FuzzerConfig()
        
        config.add_strategy("to_remove")
        config.add_strategy("to_keep")
        
        assert len(config.strategies) == 2
        
        result = config.remove_strategy("to_remove")
        assert result is True
        assert len(config.strategies) == 1
        assert config.strategies[0].name == "to_keep"
        
        # Try to remove non-existent strategy
        result = config.remove_strategy("non_existent")
        assert result is False
    
    def test_get_strategy_by_name(self):
        """Test getting a strategy by name."""
        config = FuzzerConfig()
        
        config.add_strategy("findme", weight=3.0)
        
        strategy = config.get_strategy_by_name("findme")
        assert strategy is not None
        assert strategy.name == "findme"
        assert strategy.weight == 3.0
        
        # Test non-existent strategy
        strategy = config.get_strategy_by_name("not_found")
        assert strategy is None
    
    def test_get_enabled_strategies(self):
        """Test getting only enabled strategies."""
        config = FuzzerConfig()
        
        config.add_strategy("enabled1", enabled=True)
        config.add_strategy("disabled", enabled=False)
        config.add_strategy("enabled2", enabled=True)
        
        enabled = config.get_enabled_strategies()
        assert len(enabled) == 2
        assert all(s.enabled for s in enabled)
        assert {s.name for s in enabled} == {"enabled1", "enabled2"}
    
    def test_to_dict(self):
        """Test converting configuration to dictionary."""
        config = FuzzerConfig()
        config.target_servers = ["1.2.3.4"]
        config.max_iterations = 500
        config.add_strategy("test_strategy", weight=1.5)
        
        data = config.to_dict()
        
        assert data["target_servers"] == ["1.2.3.4"]
        assert data["max_iterations"] == 500
        assert len(data["strategies"]) == 1
        assert data["strategies"][0]["name"] == "test_strategy"
        assert data["strategies"][0]["weight"] == 1.5
    
    def test_from_dict(self):
        """Test creating configuration from dictionary."""
        data = {
            "target_servers": ["9.9.9.9"],
            "max_iterations": 2000,
            "log_level": "DEBUG",
            "strategies": [
                {
                    "name": "dict_strategy",
                    "enabled": True,
                    "weight": 2.5,
                    "parameters": {"key": "value"}
                },
                "simple_strategy"  # String format
            ]
        }
        
        config = FuzzerConfig.from_dict(data)
        
        assert config.target_servers == ["9.9.9.9"]
        assert config.max_iterations == 2000
        assert config.log_level == "DEBUG"
        assert len(config.strategies) == 2
        
        # Check complex strategy
        strategy1 = config.get_strategy_by_name("dict_strategy")
        assert strategy1.weight == 2.5
        assert strategy1.parameters == {"key": "value"}
        
        # Check simple strategy
        strategy2 = config.get_strategy_by_name("simple_strategy")
        assert strategy2.enabled is True
        assert strategy2.weight == 1.0
    
    def test_save_and_load_file(self):
        """Test saving and loading configuration from file."""
        config = FuzzerConfig()
        config.target_servers = ["test.server.com"]
        config.max_iterations = 123
        config.add_strategy("file_test", weight=4.0)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            config_path = f.name
        
        try:
            # Save configuration
            config.save_to_file(config_path)
            assert os.path.exists(config_path)
            
            # Load configuration
            loaded_config = FuzzerConfig.from_file(config_path)
            
            assert loaded_config.target_servers == ["test.server.com"]
            assert loaded_config.max_iterations == 123
            assert len(loaded_config.strategies) == 1
            assert loaded_config.strategies[0].name == "file_test"
            assert loaded_config.strategies[0].weight == 4.0
            
        finally:
            if os.path.exists(config_path):
                os.unlink(config_path)
    
    def test_load_nonexistent_file(self):
        """Test loading from non-existent file."""
        with pytest.raises(FileNotFoundError):
            FuzzerConfig.from_file("nonexistent.yaml")
    
    def test_validate_valid_config(self):
        """Test validation of a valid configuration."""
        config = FuzzerConfig()
        config.add_strategy("valid_strategy")
        
        errors = config.validate_config()
        assert len(errors) == 0
    
    def test_validate_invalid_config(self):
        """Test validation of invalid configurations."""
        config = FuzzerConfig()
        
        # Invalid configurations
        config.target_servers = []  # No servers
        config.target_port = 0  # Invalid port
        config.timeout = -1  # Negative timeout
        config.max_iterations = 0  # Zero iterations
        config.concurrent_requests = -5  # Negative requests
        config.delay_between_requests = -1  # Negative delay
        config.strategy_selection_mode = "invalid_mode"
        config.log_level = "INVALID_LEVEL"
        # No strategies added
        
        errors = config.validate_config()
        
        assert len(errors) > 0
        error_text = " ".join(errors)
        assert "target server" in error_text
        assert "port" in error_text
        assert "timeout" in error_text or "Timeout" in error_text
        assert "iterations" in error_text
        assert "requests" in error_text
        assert "delay" in error_text
        assert "strategy" in error_text
        assert "log level" in error_text or "Log level" in error_text
    
    def test_validate_strategy_weights(self):
        """Test validation of strategy weights."""
        config = FuzzerConfig()
        config.add_strategy("negative_weight", weight=-1.0)
        
        errors = config.validate_config()
        
        assert len(errors) > 0
        assert any("weight" in error for error in errors)
    
    def test_validate_no_enabled_strategies(self):
        """Test validation when no strategies are enabled."""
        config = FuzzerConfig()
        config.add_strategy("disabled", enabled=False)
        
        errors = config.validate_config()
        
        assert len(errors) > 0
        assert any("enabled" in error for error in errors)


class TestHelperFunctions:
    """Test cases for helper functions."""
    
    def test_create_default_config(self):
        """Test creating default configuration."""
        config = create_default_config()
        
        assert isinstance(config, FuzzerConfig)
        assert len(config.strategies) > 0
        assert all(isinstance(s, StrategyConfig) for s in config.strategies)
        
        # Check that some expected strategies are present
        strategy_names = {s.name for s in config.strategies}
        expected_strategies = {
            "random_query_name", "random_query_type", "random_query_class",
            "random_query_id", "boundary_query_id", "long_query_name"
        }
        assert expected_strategies.issubset(strategy_names)
    
    def test_load_config_with_file(self):
        """Test loading configuration with existing file."""
        # Create a temporary config file
        config_data = """
target_servers:
  - "test.dns.com"
max_iterations: 999
strategies:
  - name: "load_test"
    weight: 3.0
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_data)
            config_path = f.name
        
        try:
            config = load_config(config_path)
            
            assert config.target_servers == ["test.dns.com"]
            assert config.max_iterations == 999
            assert len(config.strategies) == 1
            assert config.strategies[0].name == "load_test"
            assert config.strategies[0].weight == 3.0
            
        finally:
            if os.path.exists(config_path):
                os.unlink(config_path)
    
    def test_load_config_no_file(self):
        """Test loading configuration when no file exists."""
        config = load_config("nonexistent_config.yaml")
        
        # Should return default configuration
        assert isinstance(config, FuzzerConfig)
        assert len(config.strategies) > 0  # Default strategies should be loaded
    
    def test_load_config_auto_discovery(self):
        """Test automatic configuration file discovery."""
        # Create a config file in current directory
        config_data = """
target_servers:
  - "auto.discovery.com"
"""
        
        config_path = "fuzzer_config.yaml"
        
        try:
            with open(config_path, 'w') as f:
                f.write(config_data)
            
            # Load without specifying path
            config = load_config()
            
            assert config.target_servers == ["auto.discovery.com"]
            
        finally:
            if os.path.exists(config_path):
                os.unlink(config_path)


if __name__ == "__main__":
    pytest.main([__file__])