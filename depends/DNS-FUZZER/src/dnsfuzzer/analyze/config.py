"""Analyze service configuration for DNS Fuzzer."""

from typing import Dict, Any, Optional
from pathlib import Path
import yaml
from pydantic import BaseModel, Field

from ..utils.logger import get_logger

logger = get_logger(__name__)


class AnalyzeConfig(BaseModel):
    """Configuration for the analyze service."""
    # Analyze service itself
    listen_address: str = Field(default="0.0.0.0", description="Analyze service listen address")
    listen_port: int = Field(default=9100, ge=1, le=65535, description="Analyze service listen port")
    log_level: str = Field(default="INFO", description="Logging level")
    output_directory: str = Field(default="fuzzer_output/analyze", description="Directory to store analyze outputs")
    wait_time: int = Field(default=1, ge=0, description="Timeout for waiting for analyze service")

    # DNS-Monitor aggregator or child server to query
    dnsm_address: str = Field(default="127.0.0.1", description="DNS-Monitor server address")
    dnsm_port: int = Field(default=9090, ge=1, le=65535, description="DNS-Monitor server port")
    dnsm_command: Optional[str] = Field(default="", description="Optional command to send to monitor")
    dnsm_timeout: float = Field(default=2.0, ge=0.1, description="Timeout for DNS-Monitor requests")

    # Behavior
    save_responses: bool = Field(default=True, description="Save raw responses from DNS-Monitor")
    # Comparison window and toggles
    compare_window_size: int = Field(default=10, ge=1, le=1000, description="Rolling window size for comparison")
    compare_enable_cache: bool = Field(default=True, description="Enable cache comparison")
    compare_enable_resolver: bool = Field(default=True, description="Enable resolver comparison")


def load_analyze_config(config_path: Optional[str] = None) -> AnalyzeConfig:
    """Load analyze configuration from file or return defaults."""
    dft_paths = [
        "/usr/local/etc/fuzz_analyze.yaml",
        "~/.fuzz_analyze.yaml",
        "/usr/local/etc/fuzz_analyze.yml",
        "~/.fuzz_analyze.yml",
    ]
    
    if config_path and Path(config_path).exists():
        try:
            logger.info(f"Loading analyze config from: {config_path}")
            with open(config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
            return AnalyzeConfig.model_validate(data)
        except Exception as e:
            logger.warning(f"Failed to load analyze config from {config_path}: {e}")
            logger.info("Using default analyze configuration instead.")
    for _dft in dft_paths:
        if Path(_dft).exists():
            try:
                logger.info(f"Loading default analyze config from: {_dft}")
                with open(_dft, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f) or {}
                return AnalyzeConfig.model_validate(data)
            except Exception as e:
                logger.warning(f"Failed to load analyze config from {_dft}: {e}")
                logger.info("Using default analyze configuration instead.")
    return AnalyzeConfig()


def save_default_analyze_config(config_path: str = "analyze_config.yaml") -> None:
    """Write default analyze configuration to a YAML file."""
    cfg = AnalyzeConfig()
    path = Path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(cfg.model_dump(), f, default_flow_style=False, indent=2, sort_keys=False)
        logger.info(f"Default analyze configuration saved to: {path}")
    except Exception as e:
        logger.error(f"Failed to save analyze configuration: {e}")
        raise