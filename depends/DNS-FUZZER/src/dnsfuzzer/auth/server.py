"""DNS Authoritative Server for fuzzing DNS recursive resolvers."""

import asyncio
import socket
import threading
import time
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path
import json
import random
import concurrent.futures

import dns.message
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.flags

from .config import AuthConfig
from ..core.query import DNSQuery, DNSQueryBuilder
from ..core.mutator import create_default_mutator
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class AuthServerStats:
    """Statistics for the auth server."""
    requests_received: int = 0
    responses_sent: int = 0
    mutations_applied: int = 0
    errors_encountered: int = 0
    start_time: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        runtime = time.time() - self.start_time
        return {
            'requests_received': self.requests_received,
            'responses_sent': self.responses_sent,
            'mutations_applied': self.mutations_applied,
            'errors_encountered': self.errors_encountered,
            'runtime_seconds': runtime,
            'requests_per_second': self.requests_received / runtime if runtime > 0 else 0,
        }


class DNSAuthServer:
    """DNS Authoritative Server for fuzzing."""
    
    def __init__(self, config: AuthConfig):
        """Initialize the auth server."""
        self.config = config
        self.mutator = create_default_mutator(config.random_seed)
        self.stats = AuthServerStats()
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.server_thread: Optional[threading.Thread] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        
        # Setup output directory
        self.output_dir = Path(config.output_directory)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Auth server initialized with {len(config.strategies)} strategies")
        logger.info(f"Authoritative zones: {config.authoritative_zones}")
        logger.info(f"Listening on port: {config.listen_port}")
    
    def start(self) -> None:
        """Start the auth server."""
        if self.running:
            logger.warning("Auth server is already running")
            return
        
        try:
            # Create UDP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.setblocking(False)  
            self.server_socket.bind((self.config.listen_address, self.config.listen_port))
            
            self.running = True
            self.stats = AuthServerStats()  # Reset stats
            
            # Start server thread with async event loop
            self.server_thread = threading.Thread(target=self._start_async_server, daemon=True)
            self.server_thread.start()
            
            logger.info(f"Auth server started on {self.config.listen_address}:{self.config.listen_port}")
            
        except Exception as e:
            logger.error(f"Failed to start auth server: {e}")
            self.running = False
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            raise
    
    def stop(self) -> None:
        """Stop the auth server."""
        if not self.running:
            logger.warning("Auth server is not running")
            return
        
        logger.info("Stopping auth server...")
        self.running = False
        
        # Close socket
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        
        # Shutdown executor
        if self.executor:
            self.executor.shutdown(wait=True)
        
        # Wait for server thread to finish
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5.0)
        
        # Save final stats
        self._save_final_stats()
        
        logger.info("Auth server stopped")
    
    def _start_async_server(self) -> None:
        """Start the async event loop in a separate thread."""
        try:
            # Create new event loop for this thread
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            
            # Run the async server
            self.loop.run_until_complete(self._async_server_loop())
        except Exception as e:
            logger.error(f"Error in async server: {e}")
        finally:
            if self.loop:
                self.loop.close()
    
    async def _async_server_loop(self) -> None:
        """Main async server loop for handling DNS requests."""
        logger.info("Async auth server loop started")
        
        while self.running:
            try:
                # Use asyncio to handle socket operations
                data, client_addr = await self.loop.sock_recvfrom(self.server_socket, 4096)
                self.stats.requests_received += 1
                asyncio.create_task(self._async_handle_request(data, client_addr))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.running:  # Only log if we're supposed to be running
                    logger.error(f"Error in async server loop: {e}")
                    self.stats.errors_encountered += 1
                    await asyncio.sleep(0.1)  # Brief pause before retrying
        
        logger.info("Async auth server loop ended")
    
    async def _async_handle_request(self, data: bytes, client_addr: Tuple[str, int]) -> None:
        """Handle a single DNS request asynchronously."""
        try:
            # Parse DNS message
            try:
                dns_msg = dns.message.from_wire(data)
            except Exception as e:
                logger.warning(f"Failed to parse DNS message from {client_addr}: {e}")
                self.stats.errors_encountered += 1
                return
            
            # Convert to DNSQuery
            query = DNSQuery.from_dns_message(dns_msg)
            
            logger.debug(f"Received query from {client_addr}: {query.qname} {query.qtype}")
            
            # Check if we're authoritative for this domain
            if not self.config.is_authoritative_for(query.qname):
                logger.debug(f"Not authoritative for {query.qname}, ignoring")
                return
            
            # Generate response
            response = self._generate_response(query)
            
            # Apply mutations if configured
            mutation_applied = False
            mutation_type = None
            if random.random() < self.config.mutation_probability:
                try:
                    mutated_response = self.mutator.mutate(response)
                    if mutated_response != response:
                        response = mutated_response
                        mutation_applied = True
                        mutation_type = "dns_mutation"  # Could be more specific based on mutator
                        self.stats.mutations_applied += 1
                        logger.debug(f"Applied mutation to response for {query.qname}")
                except Exception as e:
                    logger.warning(f"Mutation failed for {query.qname}: {e}")
            
            # Send response asynchronously
            await self._async_send_response(response, client_addr)
            self.stats.responses_sent += 1
            
            # Save interaction if configured
            if self.config.save_interactions:
                # Run in executor to avoid blocking
                await self.loop.run_in_executor(
                    self.executor, 
                    self._save_interaction, 
                    query, response, client_addr, mutation_applied, mutation_type
                )
                
        except Exception as e:
            logger.error(f"Error handling request from {client_addr}: {e}")
            self.stats.errors_encountered += 1
    
    def _generate_response(self, query: DNSQuery) -> DNSQuery:
        """Generate a basic DNS response for the query."""
        # Create response builder
        builder = (DNSQueryBuilder()
                  .with_question(query.qname, query.qtype, query.qclass)
                  .with_flags(
                      is_response=True,
                      authoritative=True,
                      recursion_desired=query.recursion_desired,
                      recursion_available=False
                  )
                  .with_id(query.query_id))
                  
        answer_data = self._generate_answer_data(query.qname, query.qtype)
        if answer_data:
            builder.with_answer(query.qname, query.qtype, answer_data, ttl=self.config.default_ttl)
            builder.response_code(dns.rcode.NOERROR)
        else:
            # No data available
            builder.response_code(dns.rcode.NXDOMAIN)
        
        return builder.build()
    
    def _generate_answer_data(self, qname: str, qtype: str) -> Optional[str]:
        """Generate answer data based on query type."""
        # Simple answer generation - can be extended
        if qtype == "A":
            # Generate a random IP address
            return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        elif qtype == "AAAA":
            # Generate a random IPv6 address
            return f"2001:db8::{random.randint(1, 65535):x}:{random.randint(1, 65535):x}"
        elif qtype == "CNAME":
            return f"alias.{qname}"
        elif qtype == "MX":
            return f"10 mail.{qname}"
        elif qtype == "TXT":
            return f'"Generated response for {qname}"'
        elif qtype == "NS":
            return f"ns1.{qname}"
        elif qtype == "SOA":
            # Ensure absolute domain names (FQDN) for SOA record
            primary_ns = f"ns1.{qname}."
            admin_email = f"admin.{qname}."
            return f"{primary_ns} {admin_email} 1 3600 1800 604800 86400"
        else:
            # For unknown types, return None (NXDOMAIN)
            return None
    
    def _send_response(self, response: DNSQuery, client_addr: Tuple[str, int]) -> None:
        """Send DNS response to client."""
        try:
            # Convert to wire format
            dns_msg = response.to_dns_message()
            wire_data = dns_msg.to_wire()
            
            # Send response
            self.server_socket.sendto(wire_data, client_addr)
            
            logger.debug(f"Sent response to {client_addr}: {response.qname} {response.qtype}")
            
        except Exception as e:
            logger.error(f"Failed to send response to {client_addr}: {e}")
            self.stats.errors_encountered += 1
    
    async def _async_send_response(self, response: DNSQuery, client_addr: Tuple[str, int]) -> None:
        """Send DNS response to client asynchronously."""
        try:
            # Convert to wire format
            dns_msg = response.to_dns_message()
            wire_data = dns_msg.to_wire()
            
            # Send response asynchronously
            await self.loop.sock_sendto(self.server_socket, wire_data, client_addr)
            
            logger.debug(f"Sent response to {client_addr}: {response.qname} {response.qtype}")
            
        except Exception as e:
            logger.error(f"Failed to send response to {client_addr}: {e}")
            self.stats.errors_encountered += 1
    
    def _save_interaction(self, query: DNSQuery, response: DNSQuery, client_addr: Tuple[str, int], mutation_applied: bool = False, mutation_type: str = None) -> None:
        """Save query-response interaction to file."""
        try:
            interaction = {
                'timestamp': time.time(),
                'client_address': client_addr[0],
                'client_port': client_addr[1],
                'query': {
                    'id': query.query_id,
                    'qname': query.qname,
                    'qtype': query.qtype,
                    'qclass': query.qclass,
                    'flags': {
                        'recursion_desired': query.recursion_desired,
                        'authoritative': query.authoritative,
                        'truncated': query.truncated,
                        'opcode': query.opcode.name if hasattr(query.opcode, 'name') else str(query.opcode)
                    }
                },
                'response': {
                    'id': response.query_id,
                    'rcode': response.response_code.name if response.response_code else 'NOERROR',
                    'flags': {
                        'authoritative': response.authoritative,
                        'truncated': response.truncated,
                        'recursion_desired': response.recursion_desired,
                        'recursion_available': response.recursion_available,
                        'opcode': response.opcode.name if hasattr(response.opcode, 'name') else str(response.opcode)
                    },
                    'answer_count': len(response.answers),
                    'authority_count': len(response.authorities),
                    'additional_count': len(response.additional),
                    'answers': response.answers,
                    'authorities': response.authorities,
                    'additional': response.additional
                },
                'mutation': {
                    'applied': mutation_applied,
                    'type': mutation_type
                } if mutation_applied else None
            }
            
            # Save to interactions file
            interactions_file = self.output_dir / "interactions.jsonl"
            with open(interactions_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(interaction) + '\n')
                
        except Exception as e:
            logger.warning(f"Failed to save interaction: {e}")
    
    def _save_final_stats(self) -> None:
        """Save final statistics to file."""
        try:
            stats_file = self.output_dir / "auth_server_stats.json"
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.stats.to_dict(), f, indent=2)
            
            logger.info(f"Auth server statistics saved to: {stats_file}")
            logger.info(f"Final stats: {self.stats.to_dict()}")
            
        except Exception as e:
            logger.error(f"Failed to save auth server statistics: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current server statistics."""
        return self.stats.to_dict()
    
    def is_running(self) -> bool:
        """Check if the server is running."""
        return self.running
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


def run_auth(config: AuthConfig, **kwargs) -> None:
    """Run the auth server with the given configuration."""
    
    # Override config with any provided kwargs
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)
    
    # Create and run server
    server = DNSAuthServer(config)
    
    try:
        server.start()
        
        logger.info("Auth server is running. Press Ctrl+C to stop.")
        
        # Keep running until interrupted
        while server.is_running():
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.error(f"Auth server error: {e}")
    finally:
        server.stop()


if __name__ == "__main__":
    # Simple CLI for running the auth server
    import sys
    
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    run_auth(config_path)