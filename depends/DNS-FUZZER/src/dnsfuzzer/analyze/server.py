"""Analyze TCP service.

This service accepts simple TCP requests from the fuzzer client. Upon each
request it queries DNS-Monitor (aggregator or child analysis server), stores
the response, and immediately returns a short signal message to let the
fuzzer proceed.
"""

import socket
import socketserver
import threading
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any

from .config import AnalyzeConfig
from .compare import CompareEngine
from ..utils.logger import get_logger

logger = get_logger(__name__)


class AnalyzeTCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: "AnalyzeServer" = self.server  # type: ignore
        cfg = server.config
        try:
            # Read any incoming payload (optional)
            try:
                self.request.settimeout(cfg.dnsm_timeout)
                _ = self.request.recv(1024)  # we ignore content; presence indicates a tick
            except Exception:
                pass
            # Wait for analyze service to be ready
            if cfg.wait_time > 0:
                time.sleep(cfg.wait_time)

            # Query DNS-Monitor
            result = server.query_dnsm()
            # Persist
            server.persist_result(result)

            # Respond with a simple signal
            response = {"status": "ok", "signal": "continue"}
            self.request.sendall(json.dumps(response).encode('utf-8'))
        except Exception as e:
            logger.error(f"Analyze handler error: {e}")
            try:
                self.request.sendall(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))
            except Exception:
                pass
        finally:
            try:
                self.request.close()
            except Exception:
                pass


class AnalyzeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: AnalyzeConfig) -> None:
        super().__init__(address, AnalyzeTCPHandler)
        self.config = config
        self.output_dir = Path(config.output_directory)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.compare = CompareEngine(
            window_size=config.compare_window_size,
            enable_cache_compare=config.compare_enable_cache,
            enable_resolver_compare=config.compare_enable_resolver,
        )
        logger.info(f"Analyze service listening on {address[0]}:{address[1]}")

    def query_dnsm(self) -> Dict[str, Any]:
        cfg = self.config
        try:
            with socket.create_connection((cfg.dnsm_address, cfg.dnsm_port), timeout=cfg.dnsm_timeout) as s:
                if cfg.dnsm_command:
                    s.sendall(cfg.dnsm_command.encode('utf-8'))
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            return json.loads(data.decode('utf-8') or '{}')
        except Exception as e:
            logger.warning(f"Failed to query DNS-Monitor at {cfg.dnsm_address}:{cfg.dnsm_port}: {e}")
            return {"status": "error", "message": str(e)}

    def persist_result(self, result: Dict[str, Any]) -> None:
        try:
            ts = int(time.time())
            out = self.output_dir / f"analyze_{ts}.json"
            with self._lock:
                with open(out, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2)
            logger.debug(f"Saved analyze result to {out}")
            # Add into compare window and save summary
            try:
                self.compare.add_result(result)
                summary_path = self.compare.save_summary(self.output_dir)
                logger.debug(f"Saved compare summary to {summary_path}")
            except Exception as e:
                logger.warning(f"Compare summary generation failed: {e}")
        except Exception as e:
            logger.error(f"Failed to save analyze result: {e}")


def run_analyze(config: AnalyzeConfig) -> None:
    """Run the analyze TCP service (blocking)."""
    server = AnalyzeServer((config.listen_address, config.listen_port), config)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Analyze service stopped by user")
    finally:
        server.shutdown()
        server.server_close()