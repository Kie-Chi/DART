"""Configuration management for DNS Fuzzer."""

import os
import yaml
import importlib
import inspect
from typing import Dict, List, Any, Optional, Literal, Union
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator

from .. import constants
from ..utils.logger import get_logger

logger = get_logger(__name__)


class CustomPacketTarget(BaseModel):
    """Configuration for custom packet generation target."""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, description="Test name/identifier for this custom packet")
    file: str = Field(..., min_length=1, description="Python file path containing the generator function")
    func: str = Field(..., min_length=1, description="Function name to call for packet generation")

    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate name format."""
        if not v.replace('_', '').replace('-', '').replace(' ', '').isalnum():
            raise ValueError("Name must contain only alphanumeric characters, underscores, hyphens, and spaces")
        return v

    @field_validator('func')
    @classmethod
    def validate_func(cls, v: str) -> str:
        """Validate function name format."""
        if not v.replace('_', '').isalnum():
            raise ValueError("Function name must contain only alphanumeric characters and underscores")
        return v


class StrategyConfig(BaseModel):
    """Configuration for a mutation strategy."""
    model_config = ConfigDict(extra="forbid")
    
    name: str = Field(..., min_length=1, description="Strategy name")
    enabled: bool = Field(default=True, description="Whether the strategy is enabled")
    weight: float = Field(default=1.0, ge=0.0, le=100.0, description="Strategy weight for selection")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Strategy-specific parameters")
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate strategy name format."""
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError("Strategy name must contain only alphanumeric characters, underscores, and hyphens")
        return v.lower()


class BaseFuzzerConfig(BaseModel):
    """Base configuration for DNS fuzzer components."""
    model_config = ConfigDict(extra="forbid", validate_assignment=True)
    
    # Strategy configuration
    strategies: List[StrategyConfig] = Field(default_factory=list, description="List of mutation strategies")
    strategy_selection_mode: Literal["weighted_random", "round_robin", "all"] = Field(
        default="weighted_random", 
        description="Strategy selection mode"
    )
    
    # Output configuration
    output_directory: str = Field(default="fuzzer_output", min_length=1, description="Output directory path")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO", 
        description="Logging level"
    )
    
    # DNS configuration
    default_query_name: str = Field(default="example.com", min_length=1, description="Default query name")
    default_query_type: str = Field(default="A", description="Default query type")
    default_query_class: str = Field(default="IN", description="Default query class")
    
    # Seed for reproducibility
    random_seed: Optional[int] = Field(default=114514, description="Random seed for reproducibility")


class ClientConfig(BaseFuzzerConfig):
    """Configuration for DNS client fuzzer."""
    
    # Target configuration
    target_servers: List[str] = Field(
        default=["8.8.8.8", "1.1.1.1"], 
        min_length=1,
        description="List of target DNS servers"
    )
    target_port: int = Field(default=53, ge=1, le=65535, description="Target DNS port")
    timeout: float = Field(default=5.0, gt=0.0, le=300.0, description="Request timeout in seconds")
    
    # Fuzzing configuration
    max_iterations: int = Field(default=1000, ge=1, description="Maximum number of fuzzing iterations")
    query_targets: Optional[List[Union[str, Dict[str, Any]]]] = Field(
        default=None,
        description="List of query targets - either 'domain type' strings or custom packet dicts"
    )
    concurrent_requests: int = Field(default=10, ge=1, le=1000, description="Number of concurrent requests")
    delay_between_requests: float = Field(default=0.1, ge=0.0, description="Delay between requests in seconds")
    test_all_servers: bool = Field(default=True, description="Whether to send each query to all target servers")
    wait_for_analyze: bool = Field(default=False, description="Whether to wait for analyze signal after each iteration")
    analyze_wait_timeout: float = Field(default=1.5, gt=0.0, description="Timeout for waiting analyze signal in seconds")
    
    # Client-specific configuration
    save_packets: bool = Field(default=True, description="Whether to save packet data")
    save_responses: bool = Field(default=True, description="Whether to save response data")
    
    @field_validator('query_targets')
    @classmethod
    def validate_query_targets(cls, v: Optional[List[Union[str, Dict[str, Any]]]]) -> Optional[List[Union[str, CustomPacketTarget]]]:
        """Validate query targets format - supports both string and dict formats."""
        if v is None:
            return v

        validated = []
        valid_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT', 'ANY',
                       'DNSKEY', 'DS', 'RRSIG', 'NSEC', 'NSEC3', 'OPT', 'SVCB', 'HTTPS',
                       'DNAME', 'NAPTR', 'TKEY', 'TSIG', 'CAA', 'IPSECKEY']

        for target in v:
            if isinstance(target, str):
                # String format: "domain type" or just "domain"
                target = target.strip()
                if not target:
                    continue

                parts = target.split()
                if len(parts) == 1:
                    # Only domain provided, will use default_query_type
                    validated.append(target)
                elif len(parts) == 2:
                    domain, qtype = parts
                    qtype = qtype.upper()
                    if qtype not in valid_types:
                        logger.warning(f"Query type '{qtype}' may not be standard, allowing anyway")
                    validated.append(f"{domain} {qtype}")
                else:
                    raise ValueError(f"Invalid query target format '{target}'. Expected 'domain' or 'domain type'")

            elif isinstance(target, dict):
                # Dictionary format: custom packet generator
                try:
                    custom_target = CustomPacketTarget.model_validate(target)
                    validated.append(custom_target)
                except Exception as e:
                    raise ValueError(f"Invalid custom packet target format: {e}")

            else:
                raise ValueError(f"Query target must be string or dict, got {type(target)}")

        return validated if validated else None
    
    @field_validator('target_servers')
    @classmethod
    def validate_target_servers(cls, v: List[str]) -> List[str]:
        """Validate target server addresses."""
        import ipaddress
        validated_servers = []
        for server in v:
            try:
                # Try to parse as IP address
                ipaddress.ip_address(server)
                validated_servers.append(server)
            except ValueError:
                # If not IP, assume it's a hostname (basic validation)
                if not server or '.' not in server:
                    raise ValueError(f"Invalid server address: {server}")
                validated_servers.append(server)
        return validated_servers


class AuthConfig(BaseFuzzerConfig):
    """Configuration for DNS auth server fuzzer."""
    
    # Server configuration
    listen_address: str = Field(default="0.0.0.0", description="Address to listen on")
    listen_port: int = Field(default=5353, ge=1, le=65535, description="Port to listen on")
    
    # Auth-specific configuration
    authoritative_zones: List[str] = Field(
        default=["example.com", "test.local"], 
        description="Zones this server is authoritative for"
    )
    default_ttl: int = Field(default=300, ge=1, le=86400, description="Default TTL for responses")
    enable_recursion: bool = Field(default=False, description="Whether to enable recursion")
    
    # Response behavior
    response_delay: float = Field(default=0.0, ge=0.0, description="Artificial delay before responding")
    drop_probability: float = Field(default=0.0, ge=0.0, le=1.0, description="Probability of dropping requests")
    mutation_probability: float = Field(default=0.90, ge=0.0, le=1.0, description="Probability of applying mutations to responses")
    save_interactions: bool = Field(default=True, description="Whether to save query-response interactions")


# Keep the original FuzzerConfig for backward compatibility
class FuzzerConfig(ClientConfig):
    """Main configuration for the DNS fuzzer (backward compatibility)."""
    pass
    
    @field_validator('output_directory')
    @classmethod
    def validate_output_directory(cls, v: str) -> str:
        """Validate and normalize output directory path."""
        path = Path(v)
        # Convert to absolute path and normalize
        return str(path.resolve())
    
    @model_validator(mode='after')
    def validate_strategy_names_unique(self) -> 'FuzzerConfig':
        """Ensure strategy names are unique."""
        strategy_names = [s.name for s in self.strategies]
        if len(strategy_names) != len(set(strategy_names)):
            duplicates = [name for name in strategy_names if strategy_names.count(name) > 1]
            raise ValueError(f"Duplicate strategy names found: {set(duplicates)}")
        return self
    
    @classmethod
    def from_file(cls, config_path: str) -> 'FuzzerConfig':
        """Load configuration from YAML file."""
        logger.info(f"Loading configuration from: {config_path}")
        config_path = Path(config_path)
        
        if not config_path.exists():
            logger.error(f"Configuration file not found: {config_path}")
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            logger.debug(f"Loaded raw configuration data: {data}")
            return cls.from_dict(data)
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            raise ValueError(f"Invalid YAML format in {config_path}: {e}")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            raise
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FuzzerConfig':
        """Create configuration from dictionary with validation."""
        logger.debug("Creating configuration from dictionary")
        
        if not isinstance(data, dict):
            raise ValueError("Configuration data must be a dictionary")
        
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
            logger.info(f"Successfully created configuration with {len(strategies)} strategies")
            return config
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            raise ValueError(f"Configuration validation failed: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        logger.debug("Converting configuration to dictionary")
        
        # Use pydantic's model_dump method
        result = self.model_dump()
        
        # Convert strategies to dictionaries
        result['strategies'] = [
            strategy.model_dump() for strategy in self.strategies
        ]
        
        return result
    
    def save_to_file(self, config_path: str) -> None:
        """Save configuration to YAML file."""
        logger.info(f"Saving configuration to: {config_path}")
        config_path = Path(config_path)
        
        try:
            # Ensure parent directory exists
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert to dictionary and save
            config_dict = self.to_dict()
            
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2, sort_keys=False)
            
            logger.info(f"Configuration saved successfully to: {config_path}")
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            raise ValueError(f"Failed to save configuration to {config_path}: {e}")
    
    def get_enabled_strategies(self) -> List[StrategyConfig]:
        """Get list of enabled strategies."""
        enabled = [s for s in self.strategies if s.enabled]
        logger.debug(f"Found {len(enabled)} enabled strategies out of {len(self.strategies)} total")
        return enabled
    
    def get_strategy_by_name(self, name: str) -> Optional[StrategyConfig]:
        """Get strategy by name."""
        normalized_name = name.lower()
        for strategy in self.strategies:
            if strategy.name == normalized_name:
                logger.debug(f"Found strategy: {name}")
                return strategy
        logger.debug(f"Strategy not found: {name}")
        return None
    
    def add_strategy(self, name: str, enabled: bool = True, weight: float = 1.0, 
                    parameters: Optional[Dict[str, Any]] = None) -> None:
        """Add a new strategy to the configuration."""
        logger.info(f"Adding strategy: {name}")
        
        # Check if strategy already exists
        if self.get_strategy_by_name(name):
            logger.warning(f"Strategy '{name}' already exists, skipping")
            return
        
        # Create and validate new strategy
        try:
            new_strategy = StrategyConfig(
                name=name,
                enabled=enabled,
                weight=weight,
                parameters=parameters or {}
            )
            self.strategies.append(new_strategy)
            logger.info(f"Successfully added strategy: {name}")
        except Exception as e:
            logger.error(f"Error adding strategy '{name}': {e}")
            raise ValueError(f"Failed to add strategy '{name}': {e}")
    
    def remove_strategy(self, name: str) -> bool:
        """Remove a strategy by name."""
        logger.info(f"Removing strategy: {name}")
        normalized_name = name.lower()
        
        for i, strategy in enumerate(self.strategies):
            if strategy.name == normalized_name:
                removed_strategy = self.strategies.pop(i)
                logger.info(f"Successfully removed strategy: {removed_strategy.name}")
                return True
        
        logger.warning(f"Strategy not found for removal: {name}")
        return False
    
    def validate_config(self) -> List[str]:
        """Validate the configuration and return list of warnings/issues."""
        logger.debug("Validating configuration")
        warnings = []
        
        # Check for enabled strategies
        enabled_strategies = self.get_enabled_strategies()
        if not enabled_strategies:
            warnings.append("No enabled strategies found - fuzzing will not be effective")
        
        # Check strategy weights
        total_weight = sum(s.weight for s in enabled_strategies)
        if total_weight == 0:
            warnings.append("Total weight of enabled strategies is 0")
        
        # Check target servers
        if not self.target_servers:
            warnings.append("No target servers specified")
        
        # Check output directory
        try:
            output_path = Path(self.output_directory)
            if output_path.exists() and not output_path.is_dir():
                warnings.append(f"Output path exists but is not a directory: {self.output_directory}")
        except Exception as e:
            warnings.append(f"Invalid output directory path: {e}")
        
        # Check timeout and iterations
        if self.timeout > 60:
            warnings.append("Timeout is very high (>60s) - consider reducing for better performance")
        
        if self.max_iterations > 100000:
            warnings.append("Max iterations is very high (>100k) - consider reducing for reasonable runtime")
        
        # Check concurrent requests
        if self.concurrent_requests > 100:
            warnings.append("High concurrent requests (>100) may overwhelm target servers")
        
        logger.debug(f"Configuration validation completed with {len(warnings)} warnings")
        return warnings


def create_default_config() -> FuzzerConfig:
    """Create a default configuration with all available strategies dynamically loaded."""
    config = FuzzerConfig()
    
    # Dynamically discover and load all available strategies
    try:
        # Get the strategies package directory path
        strategies_package = importlib.import_module('dnsfuzzer.strategies')
        strategies_dir = Path(strategies_package.__file__).parent
        
        logger.debug(f"Loading strategies from: {strategies_dir}")
        
        # Load all Python files in the strategies directory
        loaded_strategies = []
        for py_file in strategies_dir.glob("*.py"):
            # Skip __init__.py and other special files
            if py_file.name.startswith("__"):
                continue
                
            module_name = py_file.stem
            try:
                # Import the module dynamically
                module = importlib.import_module(f'dnsfuzzer.strategies.{module_name}')
                
                # Find all MutationStrategy classes in the module
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    try:
                        from .mutator import MutationStrategy
                        from ..strategies.base import BaseMutationStrategy
                        if ((issubclass(obj, MutationStrategy) or issubclass(obj, BaseMutationStrategy)) and 
                            obj is not MutationStrategy and
                            obj is not BaseMutationStrategy and
                            not inspect.isabstract(obj)):
                            try:
                                # Create instance to get strategy name
                                strategy_instance = obj()
                                strategy_name = strategy_instance.name
                                
                                # Add strategy with default weight based on module
                                default_weight = 1.0
                                if module_name == 'basic':
                                    default_weight = 1.0
                                elif module_name == 'header':
                                    default_weight = 1.0
                                elif module_name == 'record':
                                    default_weight = 0.8
                                elif module_name == 'logical':
                                    default_weight = 0.6
                                
                                loaded_strategies.append((strategy_name, True, default_weight))
                                logger.debug(f"Found strategy: {strategy_name} from {module_name}")
                                
                            except Exception as e:
                                logger.warning(f"Failed to instantiate strategy {name} from {module_name}: {e}")
                    except ImportError as e:
                        logger.warning(f"Failed to import MutationStrategy or BaseMutationStrategy: {e}")
                        
            except Exception as e:
                logger.warning(f"Failed to load module {module_name}: {e}")
        
        # Sort strategies by name for consistent ordering
        loaded_strategies.sort(key=lambda x: x[0])
        
        # Add all discovered strategies to config
        for name, enabled, weight in loaded_strategies:
            config.add_strategy(name, enabled, weight)
        
        logger.info(f"Successfully loaded {len(loaded_strategies)} strategies dynamically")
        
    except Exception as e:
        logger.error(f"Failed to dynamically load strategies: {e}")
        # Fallback to hardcoded strategies if dynamic loading fails
        logger.warning("Falling back to hardcoded strategy list")
        default_strategies = constants.DEFAULT_STRATEGY
            
        
        for name, enabled, weight in default_strategies:
            config.add_strategy(name, enabled, weight)
    
    return config


def load_config(config_path: Optional[str] = None) -> FuzzerConfig:
    """Load configuration from file or create default."""
    if config_path is None:
        # Look for config in common locations
        possible_paths = [Path(path) for path in [
            "fuzzer_config.yaml",
            "config/fuzzer_config.yaml",
            os.path.expanduser("~/.dns_fuzzer/config.yaml"),
        ]]
        
        for path in possible_paths:
            if path.exists():
                config_path = path
                break
    
    if config_path and Path(config_path).exists():
        try:
            return FuzzerConfig.from_file(config_path)
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")
            logger.info("Using default configuration instead.")
    
    return create_default_config()


def save_default_config(config_path: str = "fuzzer_config.yaml") -> None:
    """Save a default configuration file."""
    config = create_default_config()
    config.save_to_file(config_path)
    logger.info(f"Default configuration saved to: {config_path}")


if __name__ == "__main__":
    # Create and save a sample configuration
    save_default_config()