"""Custom packet generator module for DNS Fuzzer.

This module provides functionality to load and execute custom packet generation
functions from external Python files.
"""

import importlib.util
import sys
from pathlib import Path
from typing import Dict, Any, Optional, Union

from ..core.config import CustomPacketTarget
from ..core.query import DNSQuery
from ..utils.logger import get_logger

logger = get_logger(__name__)


class CustomPacketGenerator:
    """Generator for custom DNS packets from external Python files."""

    def __init__(self, base_path: Optional[Path] = None):
        """
        Initialize the custom packet generator.

        Args:
            base_path: Base path for resolving relative file paths.
                       If None, uses current working directory.
        """
        self.base_path = base_path or Path.cwd()
        self._loaded_modules: Dict[str, Any] = {}

    def _resolve_file_path(self, file_path: str) -> Path:
        """
        Resolve the file path, handling both relative and absolute paths.

        Args:
            file_path: File path from configuration

        Returns:
            Resolved absolute path
        """
        path = Path(file_path)

        if path.is_absolute():
            return path
        else:
            # Try relative to base_path first
            resolved = self.base_path / path
            if resolved.exists():
                return resolved

            # Also try relative to current working directory
            cwd_path = Path.cwd() / path
            if cwd_path.exists():
                return cwd_path

            # Return the base_path resolved version even if it doesn't exist
            # (error will be caught during loading)
            return resolved

    def _load_module(self, file_path: Path) -> Any:
        """
        Load a Python module from a file path.

        Args:
            file_path: Path to the Python file

        Returns:
            Loaded module object
        """
        # Check if already loaded
        cache_key = str(file_path.resolve())
        if cache_key in self._loaded_modules:
            return self._loaded_modules[cache_key]

        if not file_path.exists():
            raise FileNotFoundError(f"Custom packet file not found: {file_path}")

        if not file_path.suffix == '.py':
            raise ValueError(f"File must be a Python file (.py): {file_path}")

        # Read the source code
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()

        # Load the module using importlib
        module_name = f"custom_packet_{file_path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, file_path)

        if spec is None or spec.loader is None:
            raise ImportError(f"Failed to create module spec for: {file_path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module

        # Prepare execution namespace with useful imports
        # Import dnsfuzzer modules for use in custom packet generators
        DNSQuery = None
        create_basic_query = None
        DNSQueryBuilder = None

        try:
            import dnsfuzzer
            from dnsfuzzer.core.query import DNSQuery, create_basic_query, DNSQueryBuilder
        except ImportError:
            # If dnsfuzzer is not installed as package, try to import from local path
            try:
                # Add the project root to sys.path if needed
                project_root = file_path.parent
                while project_root.parent != project_root:
                    if (project_root / 'src' / 'dnsfuzzer').exists():
                        break
                    project_root = project_root.parent

                if str(project_root / 'src') not in sys.path:
                    sys.path.insert(0, str(project_root / 'src'))

                from dnsfuzzer.core.query import DNSQuery, create_basic_query, DNSQueryBuilder
            except ImportError:
                logger.warning("Could not import dnsfuzzer.core.query - some features may not work")

        # Build the globals dictionary for the module
        module_globals = {
            '__name__': module_name,
            '__file__': str(file_path),
            '__doc__': None,
            '__package__': None,
            # Provide useful imports for the custom packet generator
            'DNSQuery': DNSQuery,
            'create_basic_query': create_basic_query,
            'DNSQueryBuilder': DNSQueryBuilder,
            'dns': __import__('dns'),
        }

        # Add dns submodule convenience imports
        try:
            module_globals['dns_message'] = __import__('dns.message', fromlist=['message'])
            module_globals['dns_flags'] = __import__('dns.flags', fromlist=['flags'])
            module_globals['dns_rdatatype'] = __import__('dns.rdatatype', fromlist=['rdatatype'])
            module_globals['dns_rdataclass'] = __import__('dns.rdataclass', fromlist=['rdataclass'])
            module_globals['dns_name'] = __import__('dns.name', fromlist=['name'])
            module_globals['dns_rdata'] = __import__('dns.rdata', fromlist=['rdata'])
            module_globals['dns_rrset'] = __import__('dns.rrset', fromlist=['rrset'])
        except ImportError:
            pass

        # Execute the source code in the prepared namespace
        try:
            exec(compile(source_code, file_path, 'exec'), module_globals)
            # Update module's __dict__ with the executed globals
            module.__dict__.update(module_globals)
        except Exception as e:
            # Remove from sys.modules if loading failed
            if module_name in sys.modules:
                del sys.modules[module_name]
            raise ImportError(f"Failed to execute module {file_path}: {e}")

        self._loaded_modules[cache_key] = module
        logger.info(f"Successfully loaded custom packet module: {file_path}")

        return module

    def generate_packet(self, target: CustomPacketTarget) -> bytes:
        """
        Generate a custom DNS packet using the specified target configuration.

        Args:
            target: CustomPacketTarget configuration

        Returns:
            Raw DNS packet bytes
        """
        file_path = self._resolve_file_path(target.file)
        logger.debug(f"Loading custom packet generator: {target.name} from {file_path}")

        try:
            module = self._load_module(file_path)
        except FileNotFoundError as e:
            logger.error(f"Custom packet file not found: {e}")
            raise
        except ImportError as e:
            logger.error(f"Failed to load custom packet module: {e}")
            raise

        # Get the generator function
        func = getattr(module, target.func, None)
        if func is None:
            raise AttributeError(
                f"Function '{target.func}' not found in module '{target.file}'"
            )

        if not callable(func):
            raise TypeError(
                f"'{target.func}' in module '{target.file}' is not callable"
            )

        # Call the generator function
        try:
            logger.debug(f"Calling generator function: {target.func}")
            result = func()
        except Exception as e:
            logger.error(f"Error executing generator function '{target.func}': {e}")
            raise RuntimeError(f"Generator function '{target.func}' failed: {e}")

        # Validate result
        if not isinstance(result, bytes):
            raise TypeError(
                f"Generator function '{target.func}' must return bytes, "
                f"got {type(result)}"
            )

        if len(result) == 0:
            raise ValueError(
                f"Generator function '{target.func}' returned empty bytes"
            )

        logger.info(f"Generated custom packet '{target.name}: {len(result)} bytes")
        return result

    def clear_cache(self) -> None:
        """Clear the loaded module cache."""
        # Remove modules from sys.modules
        for cache_key in self._loaded_modules:
            module_name = cache_key.replace('/', '_').replace('.', '_')
            if module_name in sys.modules:
                del sys.modules[module_name]

        self._loaded_modules.clear()
        logger.debug("Cleared custom packet module cache")

    def get_loaded_modules(self) -> Dict[str, str]:
        """
        Get information about loaded modules.

        Returns:
            Dictionary mapping module names to file paths
        """
        return {
            name: str(path) for path, name in self._loaded_modules.items()
        }


def create_packet_generator(base_path: Optional[Path] = None) -> CustomPacketGenerator:
    """
    Create a custom packet generator instance.

    Args:
        base_path: Base path for resolving relative file paths

    Returns:
        CustomPacketGenerator instance
    """
    return CustomPacketGenerator(base_path=base_path)