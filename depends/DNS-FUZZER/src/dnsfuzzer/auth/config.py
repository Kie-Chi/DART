"""Auth server-specific configuration for DNS Fuzzer."""

from typing import Dict, List, Any, Optional
from pathlib import Path
import yaml
from pydantic import field_validator

from ..core.config import AuthConfig as BaseAuthConfig, StrategyConfig
from ..utils.logger import get_logger

logger = get_logger(__name__)


class AuthConfig(BaseAuthConfig):
    """Extended auth server configuration with additional server-specific features."""
    
    @field_validator('authoritative_zones')
    @classmethod
    def validate_authoritative_zones(cls, v: List[str]) -> List[str]:
        """Validate authoritative zone names."""
        validated_zones = []
        for zone in v:
            if not zone or not isinstance(zone, str):
                raise ValueError(f"Invalid zone name: {zone}")
            # Normalize zone name (remove trailing dot if present)
            normalized_zone = zone.rstrip('.')
            if not normalized_zone:
                raise ValueError(f"Empty zone name: {zone}")
            validated_zones.append(normalized_zone)
        return validated_zones
    
    @classmethod
    def from_file(cls, config_path: str) -> 'AuthConfig':
        """Load auth server configuration from YAML file."""
        logger.info(f"Loading auth server configuration from: {config_path}")
        config_path = Path(config_path)
        
        if not config_path.exists():
            logger.error(f"Auth server configuration file not found: {config_path}")
            raise FileNotFoundError(f"Auth server configuration file not found: {config_path}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            logger.debug(f"Loaded raw auth server configuration data: {data}")
            return cls.from_dict(data)
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            raise ValueError(f"Invalid YAML format in {config_path}: {e}")
        except Exception as e:
            logger.error(f"Error loading auth server configuration: {e}")
            raise
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuthConfig':
        """Create auth server configuration from dictionary with validation."""
        logger.debug("Creating auth server configuration from dictionary")
        
        if not isinstance(data, dict):
            raise ValueError("Auth server configuration data must be a dictionary")
        
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
            logger.info(f"Successfully created auth server configuration with {len(strategies)} strategies")
            return config
        except Exception as e:
            logger.error(f"Auth server configuration validation failed: {e}")
            raise ValueError(f"Auth server configuration validation failed: {e}")
    
    def save_to_file(self, config_path: str) -> None:
        """Save auth server configuration to YAML file."""
        logger.info(f"Saving auth server configuration to: {config_path}")
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
            
            logger.info(f"Auth server configuration saved successfully to: {config_path}")
        except Exception as e:
            logger.error(f"Error saving auth server configuration: {e}")
            raise ValueError(f"Failed to save auth server configuration to {config_path}: {e}")
    
    def is_authoritative_for(self, domain: str) -> bool:
        """Check if this server is authoritative for the given domain."""
        domain = domain.rstrip('.').lower()
        
        for zone in self.authoritative_zones:
            zone = zone.lower()
            if domain == zone or domain.endswith(f'.{zone}'):
                return True
        return False


def create_default_auth_config() -> AuthConfig:
    """Create a default auth server configuration."""
    config = AuthConfig()
    
    # Add some default strategies for auth server-side fuzzing
    default_strategies = [
        ("response_flags", True, 1.0),
        ("response_records", True, 1.0),
        ("response_rcode", True, 0.8),
        ("response_compression", True, 0.6),
        ("response_truncation", True, 0.4),
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
    
    logger.info(f"Created default auth server configuration with {len(config.strategies)} strategies")
    return config


def load_auth_config(config_path: Optional[str] = None) -> AuthConfig:
    """Load auth server configuration from file or create default."""
    if config_path is None:
        # Look for auth server config in common locations
        possible_paths = [Path(path) for path in [
            "auth_config.yaml",
            "config/auth_config.yaml",
            "fuzzer_auth_config.yaml",
        ]]
        
        for path in possible_paths:
            if path.exists():
                config_path = path
                break
    
    if config_path and Path(config_path).exists():
        try:
            return AuthConfig.from_file(config_path)
        except Exception as e:
            logger.warning(f"Failed to load auth config from {config_path}: {e}")
            logger.info("Using default auth server configuration instead.")
    
    return create_default_auth_config()


def save_default_auth_config(config_path: str = "auth_config.yaml") -> None:
    """Save a default auth server configuration file."""
    config = create_default_auth_config()
    config.save_to_file(config_path)
    logger.info(f"Default auth server configuration saved to: {config_path}")