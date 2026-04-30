"""
Tests for RuleSet and RuleEntry classes.
"""

import pytest
from dnsbuilder.rules import Rule, Version, RuleSet, RuleEntry
from dnsbuilder import constants


class TestRuleEntry:
    """Tests for RuleEntry class."""

    def test_valid_entry_creation(self):
        """Test creating a valid RuleEntry."""
        entry = RuleEntry(range=">=1.0.0", set="valid")
        assert entry.range == ">=1.0.0"
        assert entry.set == "valid"
        assert entry.val is None

    def test_base_entry_creation(self):
        """Test creating a base RuleEntry."""
        entry = RuleEntry(range=">=1.0.0", set="base", val="22.04")
        assert entry.range == ">=1.0.0"
        assert entry.set == "base"
        assert entry.val == "22.04"

    def test_dep_entry_creation(self):
        """Test creating a dep RuleEntry."""
        entry = RuleEntry(range=">=1.0.0", set="dep", val="libuv1-dev")
        assert entry.range == ">=1.0.0"
        assert entry.set == "dep"
        assert entry.val == "libuv1-dev"

    def test_invalid_set_type(self):
        """Test that invalid set type raises ValueError."""
        with pytest.raises(ValueError, match="Invalid rule set type"):
            RuleEntry(range=">=1.0.0", set="invalid_type")

    def test_base_without_val(self):
        """Test that base without val raises ValueError."""
        with pytest.raises(ValueError, match="requires 'val'"):
            RuleEntry(range=">=1.0.0", set="base")

    def test_dep_without_val(self):
        """Test that dep without val raises ValueError."""
        with pytest.raises(ValueError, match="requires 'val'"):
            RuleEntry(range=">=1.0.0", set="dep")

    def test_matches(self):
        """Test version matching."""
        entry = RuleEntry(range="[1.0.0, 2.0.0]", set="valid")
        assert entry.matches(Version("1.5.0"))
        assert entry.matches(Version("1.0.0"))
        assert entry.matches(Version("2.0.0"))
        assert not entry.matches(Version("2.0.1"))
        assert not entry.matches(Version("0.9.0"))


class TestRuleSet:
    """Tests for RuleSet class."""

    def test_from_list(self):
        """Test creating RuleSet from list format."""
        entries = [
            {"range": "[1.0.0, 2.0.0]", "set": "valid"},
            {"range": ">=1.5.0", "val": "22.04", "set": "base"},
            {"range": ">=1.8.0", "val": "libuv1-dev", "set": "dep"},
        ]
        ruleset = RuleSet(entries)
        assert len(ruleset) == 3

    def test_evaluate_valid_version(self):
        """Test evaluating a valid version."""
        entries = [
            {"range": "[1.0.0, 2.0.0]", "set": "valid"},
            {"range": ">=1.5.0", "val": "22.04", "set": "base"},
        ]
        ruleset = RuleSet(entries)
        result = ruleset.evaluate(Version("1.7.0"))
        assert result["valid"] is True
        assert result["base"] == "22.04"

    def test_evaluate_invalid_version(self):
        """Test evaluating an invalid version."""
        entries = [
            {"range": "[1.0.0, 2.0.0]", "set": "valid"},
        ]
        ruleset = RuleSet(entries)
        result = ruleset.evaluate(Version("3.0.0"))
        assert result["valid"] is False

    def test_evaluate_accumulates_deps(self):
        """Test that dependencies accumulate from multiple rules."""
        entries = [
            {"range": ">=1.0.0", "set": "valid"},
            {"range": ">=1.5.0", "val": "libuv1-dev", "set": "dep"},
            {"range": ">=1.8.0", "val": "libnghttp2-dev", "set": "dep"},
        ]
        ruleset = RuleSet(entries)
        result = ruleset.evaluate(Version("1.9.0"))
        assert "libuv1-dev" in result["deps"]
        assert "libnghttp2-dev" in result["deps"]
        assert len(result["deps"]) == 2

    def test_evaluate_first_base_wins(self):
        """Test that first matching base rule wins."""
        entries = [
            {"range": ">=1.0.0", "set": "valid"},
            {"range": ">=1.5.0", "val": "20.04", "set": "base"},
            {"range": ">=1.8.0", "val": "22.04", "set": "base"},
        ]
        ruleset = RuleSet(entries)
        result = ruleset.evaluate(Version("1.9.0"))
        # First match should win
        assert result["base"] == "20.04"

    def test_from_legacy_dict_null_values(self):
        """Test converting legacy dict with null values."""
        legacy = {
            "[1.0.0, 2.0.0]": None,
            "1.5.0": None,
        }
        ruleset = RuleSet.from_legacy_dict(legacy)
        result = ruleset.evaluate(Version("1.5.0"))
        assert result["valid"] is True

    def test_from_legacy_dict_os_version(self):
        """Test converting legacy dict with OS version values."""
        legacy = {
            "[1.0.0, 2.0.0]": None,
            ">=1.5.0": "22.04",
        }
        ruleset = RuleSet.from_legacy_dict(legacy)
        result = ruleset.evaluate(Version("1.7.0"))
        assert result["valid"] is True
        assert result["base"] == "22.04"

    def test_from_legacy_dict_dep_values(self):
        """Test converting legacy dict with dependency values."""
        legacy = {
            "[1.0.0, 2.0.0]": None,
            ">=1.5.0": "libuv1-dev",
        }
        ruleset = RuleSet.from_legacy_dict(legacy)
        result = ruleset.evaluate(Version("1.7.0"))
        assert result["valid"] is True
        assert "libuv1-dev" in result["deps"]

    def test_is_os_version(self):
        """Test OS version detection heuristic."""
        assert RuleSet._is_os_version("22.04")
        assert RuleSet._is_os_version("20.04")
        assert RuleSet._is_os_version("14.04")
        assert RuleSet._is_os_version("3.12-slim")
        assert RuleSet._is_os_version("slim")
        assert RuleSet._is_os_version("alpine")
        assert not RuleSet._is_os_version("libuv1-dev")
        assert not RuleSet._is_os_version("build-essential")
        assert not RuleSet._is_os_version("python3-ply")


class TestRuleSetIntegration:
    """Integration tests with actual rules files."""

    def test_bind_rules_format(self):
        """Test BIND rules can be parsed."""
        # Simplified BIND rules
        entries = [
            {"range": "[9.18.0, 9.18.32]", "set": "valid"},
            {"range": ">= 9.20.0", "val": "22.04", "set": "base"},
            {"range": ">= 9.15.0", "val": "libuv1-dev", "set": "dep"},
        ]
        ruleset = RuleSet(entries)

        # Test version 9.18.20 (in valid range)
        result = ruleset.evaluate(Version("9.18.20"))
        assert result["valid"] is True
        assert "libuv1-dev" in result["deps"]

        # Test version 9.20.0 (not in valid range, but matches base/dep)
        result = ruleset.evaluate(Version("9.20.0"))
        assert result["valid"] is False  # Not in [9.18.0, 9.18.32]
        assert result["base"] == "22.04"
        assert "libuv1-dev" in result["deps"]

    def test_python_rules_format(self):
        """Test Python rules can be parsed."""
        entries = [
            {"range": "[3.9.0, 3.14.99]", "set": "valid"},
            {"range": "[3.12.0, 3.13.0)", "val": "python:3.12-slim", "set": "base"},
        ]
        ruleset = RuleSet(entries)

        result = ruleset.evaluate(Version("3.12.5"))
        assert result["valid"] is True
        assert result["base"] == "python:3.12-slim"