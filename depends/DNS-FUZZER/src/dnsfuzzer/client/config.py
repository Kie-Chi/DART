"""Client-specific configuration for DNS Fuzzer."""

from typing import Dict, Any, Optional
from pathlib import Path
import yaml

from ..core.config import ClientConfig as BaseClientConfig, StrategyConfig
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ClientConfig(BaseClientConfig):
    """Extended client configuration with additional client-specific features."""
    
    @classmethod
    def from_file(cls, config_path: str) -> 'ClientConfig':
        """Load client configuration from YAML file."""
        logger.info(f"Loading client configuration from: {config_path}")
        config_path = Path(config_path)
        
        if not config_path.exists():
            logger.error(f"Client configuration file not found: {config_path}")
            raise FileNotFoundError(f"Client configuration file not found: {config_path}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            logger.debug(f"Loaded raw client configuration data: {data}")
            return cls.from_dict(data)
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            raise ValueError(f"Invalid YAML format in {config_path}: {e}")
        except Exception as e:
            logger.error(f"Error loading client configuration: {e}")
            raise
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ClientConfig':
        """Create client configuration from dictionary with validation."""
        logger.debug("Creating client configuration from dictionary")
        
        if not isinstance(data, dict):
            raise ValueError("Client configuration data must be a dictionary")
        
        # Handle strategies separately to support different input formats
        strategies_data = data.pop('strategies', [])
        strategies = []
        
        for i, strategy_data in enumerate(strategies_data):
            try:
                if isinstance(strategy_data, dict):
                    strategies.append(StrategyConfig.model_validate(strategy_data))
                elif isinstance(strategy_data, str):
                    # Simple string format: just strategy name
                    strategies.append(StrategyConfig(name=strategy_data))
                else:
                    raise ValueError(f"Strategy must be a string or dictionary, got {type(strategy_data)}")
            except Exception as e:
                logger.error(f"Error validating strategy {i}: {e}")
                raise ValueError(f"Invalid strategy configuration at index {i}: {e}")
        
        # Create main config with validated strategies
        try:
            config = cls.model_validate(data)
            config.strategies = strategies
            logger.info(f"Successfully created client configuration with {len(strategies)} strategies")
            return config
        except Exception as e:
            logger.error(f"Client configuration validation failed: {e}")
            raise ValueError(f"Client configuration validation failed: {e}")
    
    def save_to_file(self, config_path: str) -> None:
        """Save client configuration to YAML file."""
        logger.info(f"Saving client configuration to: {config_path}")
        config_path = Path(config_path)
        
        try:
            # Ensure parent directory exists
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert to dictionary and save
            config_dict = self.model_dump()
            
            # Convert strategies to dictionaries
            config_dict['strategies'] = [
                strategy.model_dump() for strategy in self.strategies
            ]
            
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2, sort_keys=False)
            
            logger.info(f"Client configuration saved successfully to: {config_path}")
        except Exception as e:
            logger.error(f"Error saving client configuration: {e}")
            raise ValueError(f"Failed to save client configuration to {config_path}: {e}")


def create_default_client_config() -> ClientConfig:
    """Create a default client configuration."""
    config = ClientConfig()
    
    # Add some default strategies for client-side fuzzing
    default_strategies = [
        ("header_flags", True, 1.0),
        ("query_name", True, 1.0),
        ("query_type", True, 0.8),
        ("additional_records", True, 0.6),
    ]
    
    for name, enabled, weight in default_strategies:
        try:
            config.strategies.append(StrategyConfig(
                name=name,
                enabled=enabled,
                weight=weight
            ))
        except Exception as e:
            logger.warning(f"Failed to add default strategy {name}: {e}")
    
    logger.info(f"Created default client configuration with {len(config.strategies)} strategies")
    return config


def load_client_config(config_path: Optional[str] = None) -> ClientConfig:
    """Load client configuration from file or create default."""
    if config_path is None:
        # Look for client config in common locations
        possible_paths = [Path(path) for path in [
            "/usr/local/etc/fuzz_client.yaml",
            "~/.fuzz_client.yaml",
            "/usr/local/etc/fuzz_client.yml",
            "~/.fuzz_client.yml",
        ]]
        
        for path in possible_paths:
            if path.exists():
                config_path = path
                break
    
    if config_path and Path(config_path).exists():
        try:
            return ClientConfig.from_file(config_path)
        except Exception as e:
            logger.warning(f"Failed to load client config from {config_path}: {e}")
            logger.info("Using default client configuration instead.")
    
    return create_default_client_config()


def save_default_client_config(config_path: str = "client_config.yaml") -> None:
    """Save a default client configuration file."""
    config = create_default_client_config()
    config.save_to_file(config_path)
    logger.info(f"Default client configuration saved to: {config_path}")