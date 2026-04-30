"""
DNS Builder RuleSet Module

Format (List[Dict]):
    [
        {"range": "[9.0.0, 9.0.1]", "set": "valid"},
        {"range": ">= 9.20.0", "val": "22.04", "set": "base"},
        {"range": ">= 9.15.0", "val": "libuv1-dev", "set": "dep"}
    ]

Built-in Set types:
    - valid: Version validation marker (no value needed)
    - base: Set base_image or os_version
    - dep: Add build dependency package

Custom Set types:
    - Images can register custom handlers via Image.register_rule_handler()
    - Custom handlers receive (entry: RuleEntry, result: dict) and modify result
"""

import re
import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Callable, TYPE_CHECKING

from .rule import Rule
from .version import Version
from .. import constants

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Type for custom rule handlers
RuleHandler = Callable[["RuleEntry", Dict[str, Any]], None]


@dataclass
class RuleEntry:
    """
    Single rule entry in a ruleset.

    Attributes:
        range: Version range string (e.g., "[1.0.0, 2.0.0]", ">=1.5.0", "1.0.0")
        set: Rule type - "valid", "base", "dep", or custom type
        val: Value for "base" or "dep" types (None for "valid")
    """
    range: str
    set: str
    val: Optional[str] = None

    def __post_init__(self):
        """Validate the rule entry after initialization."""
        # Built-in types have strict validation
        if self.set in constants.RULE_SET_TYPES:
            if self.set in ("base", "dep") and not self.val:
                raise ValueError(
                    f"Rule set type '{self.set}' requires 'val' field"
                )
        # Custom types are allowed without validation here
        # They will be validated by the handler

    @property
    def rule(self) -> Rule:
        """Get the Rule object for version matching."""
        return Rule(self.range)

    def matches(self, version: Version) -> bool:
        """
        Check if a version matches this rule's range.

        Args:
            version: Version object to check

        Returns:
            True if version is in range, False otherwise
        """
        return version in self.rule


class RuleSet:
    """
    Collection of rule entries for version-based configuration.

    RuleSet evaluates all rules against a version and returns:
    - valid: Whether the version is valid
    - base: Base image tag (first matching "base" rule wins)
    - deps: List of dependencies (all matching "dep" rules accumulate)
    - extras: Dict of custom results from custom rule handlers
    """

    def __init__(self, entries: List[dict]):
        """
        Initialize RuleSet from a list of entry dictionaries.

        Args:
            entries: List of dicts with "range", "set", and optional "val" keys
        """
        self.entries: List[RuleEntry] = [self._parse_entry(e) for e in entries]

    def _parse_entry(self, data: dict) -> RuleEntry:
        """
        Parse a dictionary into a RuleEntry.

        Args:
            data: Dictionary with rule data

        Returns:
            RuleEntry object
        """
        return RuleEntry(
            range=data["range"],
            set=data["set"],
            val=data.get("val")
        )

    def evaluate(
        self,
        version: Version,
        handlers: Optional[Dict[str, RuleHandler]] = None
    ) -> Dict[str, Any]:
        """
        Evaluate all rules for a given version.

        Args:
            version: Version object to evaluate
            handlers: Optional dict mapping custom set types to handler functions.
                      Handler signature: (entry: RuleEntry, result: dict) -> None

        Returns:
            Dictionary with:
                - "valid": bool - Whether version is valid
                - "base": Optional[str] - Base image tag (first match wins)
                - "deps": List[str] - Dependencies (all matches accumulate)
                - "extras": Dict[str, Any] - Custom results from handlers
        """
        result: Dict[str, Any] = {
            "valid": False,
            "base": None,
            "deps": [],
            "extras": {}
        }

        handlers = handlers or {}

        for entry in self.entries:
            if not entry.matches(version):
                continue

            if entry.set == "valid":
                result["valid"] = True
            elif entry.set == "base":
                # First match wins for base image
                if result["base"] is None:
                    result["base"] = entry.val
            elif entry.set == "dep":
                # All matches accumulate for dependencies
                result["deps"].append(entry.val)
            elif entry.set in handlers:
                # Custom handler
                handlers[entry.set](entry, result)
            else:
                logger.warning(f"Unknown rule set type '{entry.set}' in rule entry")

        return result

    @classmethod
    def from_legacy_dict(cls, data: dict) -> "RuleSet":
        """
        Convert legacy dict format to new RuleSet.

        Legacy format: {"[1.0, 2.0]": null} or {"[1.0, 2.0]": "value"}

        Args:
            data: Legacy dict format ruleset

        Returns:
            RuleSet instance
        """
        entries = []
        for range_str, val in data.items():
            if val is None:
                entries.append({"range": range_str, "set": "valid"})
            else:
                # Try to determine type from value
                if cls._is_os_version(val):
                    entries.append({"range": range_str, "val": val, "set": "base"})
                else:
                    entries.append({"range": range_str, "val": val, "set": "dep"})
        return cls(entries)

    @staticmethod
    def _is_os_version(val: str) -> bool:
        """
        Heuristic to detect if a value is an OS version/base image tag.

        Matches:
            - "14.04", "22.04" (Ubuntu version numbers)
            - "3.12-slim", "3.10-slim" (Python slim tags)
            - "slim", "alpine" (common tag suffixes)

        Does NOT match:
            - "libuv1-dev", "build-essential" (package names with dashes)
        """
        # OS version patterns: X.YY or X.Y-slim
        if re.match(r"^\d+\.\d+(-\w+)?$", val):
            return True
        # Common base image tag suffixes
        if val in ("slim", "alpine", "buster", "bullseye", "bookworm"):
            return True
        return False

    def __len__(self) -> int:
        return len(self.entries)

    def __repr__(self) -> str:
        return f"RuleSet({len(self.entries)} entries)"