"""
DNS Builder Rules Module

- Rule: Rule for version constraint handling
- Version: Version constraint handling
- RuleSet: Collection of rules for version-based configuration
- RuleEntry: Single rule entry
- RuleHandler: Type alias for custom rule handler functions

Usage:
    from dnsbuilder.rules import Rule, Version, RuleSet, RuleEntry, RuleHandler
"""

from .rule import Rule
from .version import Version
from .ruleset import RuleSet, RuleEntry, RuleHandler

__all__ = [
    'Rule',
    'Version',
    'RuleSet',
    'RuleEntry',
    'RuleHandler',
]

