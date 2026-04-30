"""DNS Mutator module for applying mutation strategies to DNS queries."""

import random
import importlib
import inspect
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path
import sys

from .query import DNSQuery
from ..exceptions import NoSuchStrategyError
from ..utils.logger import get_logger

logger = get_logger(__name__)


class MutationStrategy(ABC):
    """Abstract base class for DNS mutation strategies."""
    
    def __init__(self, name: str, description: str = "", weight: float = 1.0):
        """
        Initialize mutation strategy.
        
        Args:
            name: Strategy name
            description: Strategy description
            weight: Strategy selection weight (higher = more likely to be selected)
        """
        self.name = name
        self.description = description
        self.weight = weight
    
    @abstractmethod
    def mutate(self, query: DNSQuery, rng: random.Random, **kwargs) -> DNSQuery:
        """
        Apply mutation to a DNS query.
        
        Args:
            query: Original DNS query
            rng: Random number generator for reproducible mutations
            **kwargs: Additional strategy-specific parameters
            
        Returns:
            Mutated DNS query
        """
        pass
    
    def can_mutate(self, query: DNSQuery) -> bool:
        """
        Check if this strategy can be applied to the given query.
        
        Args:
            query: DNS query to check
            
        Returns:
            True if strategy can be applied, False otherwise
        """
        return True
    
    def get_mutation_info(self) -> Dict[str, Any]:
        """
        Get information about this mutation strategy.
        
        Returns:
            Dictionary containing strategy metadata
        """
        return {
            'name': self.name,
            'description': self.description,
            'weight': self.weight,
            'class': self.__class__.__name__
        }


class DNSMutator:
    """Main DNS mutator class that manages and applies mutation strategies."""
    
    def __init__(self, seed: Optional[int] = None):
        """
        Initialize DNS mutator.
        
        Args:
            seed: Random seed for reproducible mutations
        """
        self.strategies: Dict[str, MutationStrategy] = {}
        if seed is None:
            seed = 114514 # :)
        # Ensure seed is a valid type for random.Random()
        if isinstance(seed, (int, float, str, bytes, bytearray)) or seed is None:
            self.rng = random.Random(seed)
        else:
            logger.warning(f"Invalid seed type: {type(seed)}, using default")
            self.rng = random.Random(114514)
        self._history: List[Dict[str, Any]] = []
    
    def register_strategy(self, strategy: MutationStrategy) -> None:
        """
        Register a mutation strategy.
        
        Args:
            strategy: Mutation strategy to register
        """
        self.strategies[strategy.name] = strategy
        logger.debug(f"Registered mutation strategy: {strategy.name}")
    
    def unregister_strategy(self, name: str) -> bool:
        """
        Unregister a mutation strategy.
        
        Args:
            name: Name of strategy to unregister
            
        Returns:
            True if strategy was found and removed, False otherwise
        """
        result = self.strategies.pop(name, None) is not None
        if result:
            logger.debug(f"Unregistered mutation strategy: {name}")
        else:
            logger.warning(f"Attempted to unregister non-existent strategy: {name}")
        return result
    
    def list_strategies(self) -> List[Dict[str, Any]]:
        """
        List all registered strategies.
        
        Returns:
            List of strategy information dictionaries
        """
        return [strategy.get_mutation_info() for strategy in self.strategies.values()]
    
    def get_strategy(self, name: str) -> Optional[MutationStrategy]:
        """
        Get a strategy by name.
        
        Args:
            name: Strategy name
            
        Returns:
            Strategy instance or None if not found
        """
        return self.strategies.get(name)
    
    def mutate(self, query: DNSQuery, strategy_name: Optional[str] = None,
               num_mutations: int = 1) -> DNSQuery:
        """
        Apply mutation(s) to a DNS query.
        
        Args:
            query: Original DNS query
            strategy_name: Specific strategy to use (None for random selection)
            num_mutations: Number of mutations to apply
            
        Returns:
            Mutated DNS query
        """
        if not self.strategies:
            logger.error("No mutation strategies registered")
            raise NoSuchStrategyError("No mutation strategies registered")
        
        logger.debug(f"Starting mutation with {num_mutations} mutations, strategy: {strategy_name or 'random'}")
        
        mutated_query = query.clone()
        applied_strategies = []
        
        for i in range(num_mutations):
            if strategy_name:
                strategy = self.strategies.get(strategy_name)
                if not strategy:
                    logger.error(f"Strategy '{strategy_name}' not found")
                    raise NoSuchStrategyError(f"Strategy '{strategy_name}' not found")
            else:
                strategy = self._sample(mutated_query)
                if not strategy:
                    logger.warning(f"No applicable strategies found for mutation {i+1}")
                    break  # No applicable strategies found
            
            # Apply mutation
            logger.debug(f"Applying strategy '{strategy.name}' for mutation {i+1}")
            mutated_query = strategy.mutate(mutated_query, self.rng)
            applied_strategies.append(strategy.name)
        
        # Record mutation history
        self._history.append({
            'original_id': query.query_id,
            'mutated_id': mutated_query.query_id,
            'strategies': applied_strategies,
            'num_mutations': len(applied_strategies)
        })
        
        logger.info(f"Mutation completed. Applied strategies: {applied_strategies}")
        return mutated_query
    
    def mutate_batch(self, queries: List[DNSQuery], 
                    mutations_per_query: int = 1) -> List[DNSQuery]:
        """
        Apply mutations to a batch of DNS queries.
        
        Args:
            queries: List of original DNS queries
            mutations_per_query: Number of mutations to apply per query
            
        Returns:
            List of mutated DNS queries
        """
        return [self.mutate(query, num_mutations=mutations_per_query) 
                for query in queries]
    
    def _sample(self, query: DNSQuery) -> Optional[MutationStrategy]:
        """
        Select a random strategy sample based on weights and applicability.
        
        Args:
            query: DNS query to mutate
            
        Returns:
            Selected strategy or None if no applicable strategies
        """
        applicable_strategies = [
            strategy for strategy in self.strategies.values()
            if strategy.can_mutate(query)
        ]
        
        if not applicable_strategies:
            return None
        
        # Weighted random selection
        weights = [strategy.weight for strategy in applicable_strategies]
        return self.rng.choices(applicable_strategies, weights=weights)[0]
    
    def get_mutation_stats(self) -> Dict[str, int]:
        """
        Get mutation statistics from history.
        
        Returns:
            Dictionary mapping strategy names to mutation counts
        """
        stats = {}
        for record in self._history:
            strategy_name = record.get('strategy')
            if strategy_name:
                stats[strategy_name] = stats.get(strategy_name, 0) + 1
        return stats
    
    def get_history(self) -> List[Dict[str, Any]]:
        """
        Get the mutation history.
        
        Returns:
            List of mutation records
        """
        return self._history.copy()
    
    def clear_history(self) -> None:
        """Clear the mutation history."""
        self._history.clear()
    
    def load_from_mod(self, module_path: str) -> int:
        """
        load_from_mod mutation strategies from a Python module.
        
        Args:
            module_path: Path to Python module containing strategies
            
        Returns:
            Number of strategies load_from_moded
        """
        logger.debug(f"Loading strategies from module: {module_path}")
        try:
            # Add module directory to path if needed
            module_file = Path(module_path)
            if module_file.exists():
                sys.path.insert(0, str(module_file.parent))
                module_name = module_file.stem
            else:
                module_name = module_path
            
            # Import module
            module = importlib.import_module(module_name)
            
            # Find strategy classes
            load_from_moded_count = 0
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, MutationStrategy) and 
                    obj is not MutationStrategy and
                    not inspect.isabstract(obj)):
                    
                    # Instantiate and register strategy
                    try:
                        strategy_instance = obj()
                        self.register_strategy(strategy_instance)
                        load_from_moded_count += 1
                        logger.debug(f"Loaded strategy: {name}")
                    except Exception as e:
                        logger.warning(f"Failed to instantiate strategy {name}: {e}")
            
            logger.info(f"Successfully loaded {load_from_moded_count} strategies from {module_path}")
            return load_from_moded_count
            
        except Exception as e:
            logger.error(f"Failed to load strategies from {module_path}: {e}")
            raise ImportError(f"Failed to load_from_mod strategies from {module_path}: {e}")
    
    def load_from_dir(self, directory_path: str) -> int:
        """
        load_from_mod all mutation strategies from Python files in a directory.
        
        Args:
            directory_path: Path to directory containing strategy modules
            
        Returns:
            Total number of strategies load_from_moded
        """
        logger.debug(f"Loading strategies from directory: {directory_path}")
        directory = Path(directory_path)
        if not directory.exists() or not directory.is_dir():
            logger.error(f"Directory {directory_path} does not exist")
            raise ValueError(f"Directory {directory_path} does not exist")
        
        total_load_from_moded = 0
        for py_file in directory.glob("*.py"):
            if py_file.name.startswith("__"):
                continue  # Skip __init__.py and similar files
            
            try:
                # Convert file path to module name
                module_name = f"dnsfuzzer.strategies.{py_file.stem}"
                load_from_moded = self.load_from_mod(module_name)
                total_load_from_moded += load_from_moded
                logger.debug(f"Loaded {load_from_moded} strategies from {py_file.name}")
            except Exception as e:
                logger.warning(f"Failed to load strategies from {py_file.name}: {e}")
        
        logger.info(f"Total loaded {total_load_from_moded} strategies from directory {directory_path}")
        return total_load_from_moded
    
    def create_strategy_chain(self, strategy_names: List[str]) -> Callable[[DNSQuery], DNSQuery]:
        """
        Create a chain of mutation strategies.
        
        Args:
            strategy_names: List of strategy names to chain
            
        Returns:
            Function that applies all strategies in sequence
        """
        strategies = []
        for name in strategy_names:
            strategy = self.strategies.get(name)
            if not strategy:
                raise NoSuchStrategyError(f"Strategy '{name}' not found")
            strategies.append(strategy)
        
        def apply_chain(query: DNSQuery) -> DNSQuery:
            mutated = query.clone()
            for strategy in strategies:
                if strategy.can_mutate(mutated):
                    mutated = strategy.mutate(mutated, self.rng)
            return mutated
        
        return apply_chain
    
    def set_seed(self, seed: int) -> None:
        """
        Set the random seed for reproducible mutations.
        
        Args:
            seed: Random seed value
        """
        if isinstance(seed, (int, float, str, bytes, bytearray)) or seed is None:
            self.rng = random.Random(seed)
        else:
            logger.warning(f"Invalid seed type: {type(seed)}, using default")
            self.rng = random.Random(114514)


# Utility functions for creating common mutator configurations

def create_default_mutator(seed: Optional[int] = None) -> DNSMutator:
    """
    Create a mutator with default strategies dynamically loaded from strategies directory.
    
    Args:
        seed: Random seed for reproducible mutations
        
    Returns:
        Configured DNS mutator with all available strategies
    """
    mutator = DNSMutator(seed)
    
    # Dynamically load all strategies from the strategies package
    try:
        # Get the strategies package directory path
        strategies_package = importlib.import_module('dnsfuzzer.strategies')
        strategies_dir = Path(strategies_package.__file__).parent
        
        logger.debug(f"Loading strategies from: {strategies_dir}")
        
        # Load all Python files in the strategies directory
        loaded_count = 0
        for py_file in strategies_dir.glob("*.py"):
            # Skip __init__.py and other special files
            if py_file.name.startswith("__"):
                continue
                
            module_name = py_file.stem
            try:
                # Import the module dynamically
                module = importlib.import_module(f'dnsfuzzer.strategies.{module_name}')
                
                # Find and register all MutationStrategy classes in the module
                strategy_count = 0
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    try:
                        # Import BaseMutationStrategy for checking
                        from ..strategies.base import BaseMutationStrategy
                        
                        # Check if it's a strategy class (either MutationStrategy or BaseMutationStrategy subclass)
                        if ((issubclass(obj, MutationStrategy) or issubclass(obj, BaseMutationStrategy)) and 
                            obj is not MutationStrategy and
                            obj is not BaseMutationStrategy and
                            not inspect.isabstract(obj)):
                            try:
                                strategy_instance = obj()
                                mutator.register_strategy(strategy_instance)
                                strategy_count += 1
                                logger.debug(f"Registered strategy: {strategy_instance.name} from {module_name}")
                            except Exception as e:
                                logger.warning(f"Failed to instantiate strategy {name} from {module_name}: {e}")
                    except ImportError:
                        # Fallback to only checking MutationStrategy if BaseMutationStrategy import fails
                        if (issubclass(obj, MutationStrategy) and 
                            obj is not MutationStrategy and
                            not inspect.isabstract(obj)):
                            try:
                                strategy_instance = obj()
                                mutator.register_strategy(strategy_instance)
                                strategy_count += 1
                                logger.debug(f"Registered strategy: {strategy_instance.name} from {module_name}")
                            except Exception as e:
                                logger.warning(f"Failed to instantiate strategy {name} from {module_name}: {e}")
                
                if strategy_count > 0:
                    loaded_count += strategy_count
                    logger.debug(f"Loaded {strategy_count} strategies from {module_name}.py")
                    
            except Exception as e:
                logger.warning(f"Failed to load module {module_name}: {e}")
        
        logger.info(f"Successfully loaded {loaded_count} strategies from {len(list(strategies_dir.glob('*.py')))} modules")
        
    except Exception as e:
        logger.error(f"Failed to dynamically load strategies: {e}")
        # Fallback to hardcoded loading if dynamic loading fails
        try:
            from ..strategies import basic, header, record, logical
            
            for module in [basic, header, record, logical]:
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (issubclass(obj, MutationStrategy) and 
                        obj is not MutationStrategy and
                        not inspect.isabstract(obj)):
                        try:
                            strategy_instance = obj()
                            mutator.register_strategy(strategy_instance)
                        except Exception:
                            pass
                            
        except ImportError:
            logger.warning("No strategies could be loaded")
    
    return mutator