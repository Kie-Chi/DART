"""DNS Fuzzer Client implementation."""

import asyncio
import socket
import time
import random
from typing import List, Dict, Any, Optional, AsyncGenerator
from pathlib import Path
import json
from dataclasses import asdict

from .config import ClientConfig
from .analyze_interface import create_analyze_interface, AnalyzeInterface
from .packet_generator import CustomPacketGenerator, create_packet_generator
from ..core.query import DNSQuery, create_basic_query
from ..core.config import CustomPacketTarget
from ..core.mutator import create_default_mutator
from ..utils.logger import get_logger

logger = get_logger(__name__)


class DNSFuzzerClient:
    """DNS fuzzer client for sending mutated queries to target servers."""
    
    def __init__(self, config: ClientConfig):
        """Initialize the DNS fuzzer client."""
        self.config = config
        self.mutator = create_default_mutator(config.random_seed)
        self.packet_generator: Optional[CustomPacketGenerator] = None
        self.results: List[Dict[str, Any]] = []
        self.stats = {
            'queries_sent': 0,
            'responses_received': 0,
            'timeouts': 0,
            'errors_encountered': 0,
            'mutations_applied': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Initialize analyze interface if wait_for_analyze is enabled
        self.analyze_interface: Optional[AnalyzeInterface] = None
        if config.wait_for_analyze:
            # Prefer TCP interface to local analyze service; fallback to mock
            try:
                self.analyze_interface = create_analyze_interface(
                    interface_type="tcp",
                    host="127.0.0.1",
                    port=9100,
                )
            except Exception:
                self.analyze_interface = create_analyze_interface(
                    interface_type="mock",
                    simulate_delay=config.analyze_wait_timeout
                )
        
        # Set random seed if provided
        if config.random_seed is not None:
            # Ensure the seed is a valid type for random.seed()
            if isinstance(config.random_seed, (int, float, str, bytes, bytearray)):
                random.seed(config.random_seed)
                logger.info(f"Set random seed to {config.random_seed}")
            else:
                logger.warning(f"Invalid random seed type: {type(config.random_seed)}, using default")
    
    def run_fuzzing(self) -> None:
        """Run the fuzzing process synchronously."""
        asyncio.run(self.start_fuzzing())
    
    async def start_fuzzing(self) -> None:
        logger.info("Starting DNS fuzzing client")
        logger.info(f"Target servers: {self.config.target_servers}")
        
        # Check if using query_targets mode or max_iterations mode
        if self.config.query_targets:
            logger.info(f"Query targets mode: {len(self.config.query_targets)} targets")
            # Convert targets to string representation for logging
            target_strs = []
            for t in self.config.query_targets:
                if isinstance(t, str):
                    target_strs.append(t)
                elif isinstance(t, CustomPacketTarget):
                    target_strs.append(f"custom:{t.name}")
                else:
                    target_strs.append(str(t))
            logger.info(f"Targets: {', '.join(target_strs)}")
        else:
            logger.info(f"Max iterations: {self.config.max_iterations}")
        
        logger.info(f"Concurrent requests: {self.config.concurrent_requests}")
        if self.config.wait_for_analyze:
            logger.info(f"Wait for analyze enabled with timeout: {self.config.analyze_wait_timeout}s")
        
        self.stats['start_time'] = time.time()
        
        # Create output directory
        output_path = Path(self.config.output_directory)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.config.concurrent_requests)
        
        # Choose fuzzing mode based on configuration
        if self.config.query_targets:
            # Use query targets mode
            await self._run_with_query_targets(semaphore)
        elif self.config.wait_for_analyze:
            # Use analyze wait mode
            await self._run_with_analyze_wait(semaphore)
        else:
            # Use standard max iterations mode
            await self._run_without_analyze_wait(semaphore)
        
        self.stats['end_time'] = time.time()
        
        # Save results
        await self._save_results()
        
        # Print summary
        self._print_summary()
    
    async def _run_with_query_targets(self, semaphore: asyncio.Semaphore) -> None:
        """Run fuzzing with specific query targets (one pass through all targets)."""
        iteration = 0

        # Initialize packet generator if needed (for custom packet targets)
        has_custom_packets = any(
            isinstance(t, CustomPacketTarget) for t in self.config.query_targets
        )
        if has_custom_packets:
            self.packet_generator = create_packet_generator(
                base_path=Path(self.config.output_directory)
            )

        for target_spec in self.config.query_targets:
            # Handle different target formats
            if isinstance(target_spec, CustomPacketTarget):
                # Custom packet format
                await self._process_custom_packet_target(semaphore, target_spec, iteration)
                iteration += 1
            elif isinstance(target_spec, str):
                # String format: "domain type"
                await self._process_string_target(semaphore, target_spec, iteration)
                iteration += 1
            else:
                logger.warning(f"Unknown target format: {type(target_spec)}, skipping")
                iteration += 1
                continue

        logger.info(f"Completed fuzzing {len(self.config.query_targets)} query targets")

    async def _process_custom_packet_target(
        self, semaphore: asyncio.Semaphore, target: CustomPacketTarget, iteration: int
    ) -> None:
        """Process a custom packet target."""
        logger.info(f"Processing custom packet target: {target.name}")

        try:
            # Generate custom packet bytes
            packet_bytes = self.packet_generator.generate_packet(target)
            logger.debug(f"Generated {len(packet_bytes)} bytes for '{target.name}'")

            # Create tasks for this iteration
            iteration_tasks = []

            # Generate queries for target servers
            if self.config.test_all_servers:
                for server_idx, target_server in enumerate(self.config.target_servers):
                    query_data = {
                        'iteration': iteration,
                        'server_index': server_idx,
                        'target_server': target_server,
                        'target_port': self.config.target_port,
                        'raw_packet_bytes': packet_bytes,
                        'query_target': f"custom:{target.name}",
                        'timestamp': time.time()
                    }
                    task = asyncio.create_task(
                        self._send_custom_packet(semaphore, query_data)
                    )
                    iteration_tasks.append(task)
            else:
                target_server = random.choice(self.config.target_servers)
                query_data = {
                    'iteration': iteration,
                    'server_index': 0,
                    'target_server': target_server,
                    'target_port': self.config.target_port,
                    'raw_packet_bytes': packet_bytes,
                    'query_target': f"custom:{target.name}",
                    'timestamp': time.time()
                }
                task = asyncio.create_task(
                    self._send_custom_packet(semaphore, query_data)
                )
                iteration_tasks.append(task)

            # Wait for all queries to complete
            logger.info(f"Waiting for iteration {iteration} ({target.name}) queries to complete")
            await asyncio.gather(*iteration_tasks, return_exceptions=True)

            # Wait for analyze signal if enabled
            if self.config.wait_for_analyze:
                logger.info(f"Waiting for analyze signal (timeout: {self.config.analyze_wait_timeout}s)")
                if self.analyze_interface:
                    try:
                        await self.analyze_interface.send_iteration_data({
                            'iteration': iteration,
                            'targets': self.config.target_servers,
                            'query_target': f"custom:{target.name}",
                            'timestamp': time.time(),
                        })
                    except Exception:
                        pass
                await self._wait_for_analyze_signal()

            # Add delay between iterations
            if self.config.delay_between_requests > 0:
                await asyncio.sleep(self.config.delay_between_requests)

        except Exception as e:
            logger.error(f"Error processing custom packet target '{target.name}': {e}")

    async def _process_string_target(
        self, semaphore: asyncio.Semaphore, target_spec: str, iteration: int
    ) -> None:
        """Process a string format target (domain type)."""
        # Parse target specification
        parts = target_spec.strip().split()
        if len(parts) == 2:
            qname, qtype = parts
        else:
            qname = parts[0]
            qtype = self.config.default_query_type

        logger.debug(f"Processing target: {qname} {qtype}")

        # Create base query for this target
        base_query = create_basic_query(qname=qname, qtype=qtype)
        base_query.qclass = self.config.default_query_class

        # Do Not Apply mutations
        try:
            mutated_query = base_query

            # Create tasks for this iteration (this target)
            iteration_tasks = []

            # Generate queries for target servers
            if self.config.test_all_servers:
                # Send to all servers
                for server_idx, target_server in enumerate(self.config.target_servers):
                    query_data = {
                        'iteration': iteration,
                        'server_index': server_idx,
                        'target_server': target_server,
                        'target_port': self.config.target_port,
                        'original_query': base_query,
                        'mutated_query': mutated_query,
                        'query_target': target_spec,
                        'timestamp': time.time()
                    }
                    task = asyncio.create_task(
                        self._send(semaphore, query_data)
                    )
                    iteration_tasks.append(task)
            else:
                # Send to one random server
                target_server = random.choice(self.config.target_servers)
                query_data = {
                    'iteration': iteration,
                    'server_index': 0,
                    'target_server': target_server,
                    'target_port': self.config.target_port,
                    'original_query': base_query,
                    'mutated_query': mutated_query,
                    'query_target': target_spec,
                    'timestamp': time.time()
                }
                task = asyncio.create_task(
                    self._send(semaphore, query_data)
                )
                iteration_tasks.append(task)

            # Wait for all queries in this iteration to complete
            logger.info(f"Waiting for iteration {iteration} ({target_spec}) queries to complete")
            await asyncio.gather(*iteration_tasks, return_exceptions=True)

            # Wait for analyze signal if enabled
            if self.config.wait_for_analyze:
                logger.info(f"Waiting for analyze signal (timeout: {self.config.analyze_wait_timeout}s)")
                # Send iteration summary to analyze interface first
                if self.analyze_interface:
                    try:
                        await self.analyze_interface.send_iteration_data({
                            'iteration': iteration,
                            'targets': self.config.target_servers,
                            'query_target': target_spec,
                            'timestamp': time.time(),
                        })
                    except Exception:
                        pass
                await self._wait_for_analyze_signal()

            # Add delay between iterations
            if self.config.delay_between_requests > 0:
                await asyncio.sleep(self.config.delay_between_requests)

        except Exception as e:
            logger.error(f"Error processing target '{target_spec}': {e}")
    
    async def _run_without_analyze_wait(self, semaphore: asyncio.Semaphore) -> None:
        """Run fuzzing without waiting for analyze signals (original behavior)."""
        tasks = []
        query_count = 0
        async for query_data in self._generate_queries():
            task = asyncio.create_task(
                self._send(semaphore, query_data)
            )
            tasks.append(task)
            query_count += 1
            expected_queries = (self.config.max_iterations * len(self.config.target_servers) if self.config.test_all_servers else self.config.max_iterations)
            
            if query_count >= expected_queries:
                break
            
            # Add delay between request creation
            if self.config.delay_between_requests > 0:
                await asyncio.sleep(self.config.delay_between_requests)
        
        # Wait for all tasks to complete
        logger.info(f"Waiting for {len(tasks)} queries to complete")
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _run_with_analyze_wait(self, semaphore: asyncio.Semaphore) -> None:
        """Run fuzzing with waiting for analyze signals after each iteration."""
        iteration = 0
        
        while iteration < self.config.max_iterations:
            # Generate queries for current iteration
            iteration_tasks = []
            
            # Create base query
            base_query = create_basic_query(
                qname=self.config.default_query_name,
                qtype=self.config.default_query_type
            )
            base_query.qclass = self.config.default_query_class
            
            # Apply mutations
            try:
                mutated_query = self.mutator.mutate(base_query)
                
                # Check if mutation was actually applied
                if mutated_query != base_query:
                    self.stats['mutations_applied'] += 1
                
                # Generate queries for target servers
                if self.config.test_all_servers:
                    # Send to all servers
                    for server_idx, target_server in enumerate(self.config.target_servers):
                        query_data = {
                            'iteration': iteration,
                            'server_index': server_idx,
                            'target_server': target_server,
                            'target_port': self.config.target_port,
                            'original_query': base_query,
                            'mutated_query': mutated_query,
                            'timestamp': time.time()
                        }
                        task = asyncio.create_task(
                            self._send(semaphore, query_data)
                        )
                        iteration_tasks.append(task)
                else:
                    # Original behavior: select one server randomly
                    target_server = random.choice(self.config.target_servers)
                    query_data = {
                        'iteration': iteration,
                        'server_index': 0,
                        'target_server': target_server,
                        'target_port': self.config.target_port,
                        'original_query': base_query,
                        'mutated_query': mutated_query,
                        'timestamp': time.time()
                    }
                    task = asyncio.create_task(
                        self._send(semaphore, query_data)
                    )
                    iteration_tasks.append(task)
                
                # Wait for all queries in this iteration to complete
                logger.info(f"Waiting for iteration {iteration} queries to complete")
                await asyncio.gather(*iteration_tasks, return_exceptions=True)

                # Wait for analyze signal (simulated with sleep for now)
                logger.info(f"Waiting for analyze signal (timeout: {self.config.analyze_wait_timeout}s)")
                # send iteration summary to analyze interface first
                if self.analyze_interface:
                    try:
                        await self.analyze_interface.send_iteration_data({
                            'iteration': iteration,
                            'targets': self.config.target_servers,
                            'timestamp': time.time(),
                        })
                    except Exception:
                        pass
                await self._wait_for_analyze_signal()
                
                iteration += 1
                
            except Exception as e:
                logger.error(f"Error in iteration {iteration}: {e}")
                iteration += 1
                continue
    
    async def _wait_for_analyze_signal(self) -> None:
        """Wait for analyze signal using the analyze interface."""
        if self.analyze_interface:
            try:
                signal_received = await self.analyze_interface.wait_for_signal(
                    timeout=self.config.analyze_wait_timeout
                )
                if signal_received:
                    logger.debug("Analyze signal received")
                else:
                    logger.warning("Analyze signal timeout, proceeding anyway")
            except Exception as e:
                logger.error(f"Error waiting for analyze signal: {e}")
                logger.info("Proceeding without analyze signal")
        else:
            # Fallback to simple sleep if no interface available
            await asyncio.sleep(self.config.analyze_wait_timeout)
            logger.debug("Analyze signal simulated with sleep")
    
    async def _generate_queries(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Generate DNS queries for fuzzing."""
        iteration = 0
        
        while iteration < self.config.max_iterations:
            # Create base query
            base_query = create_basic_query(
                qname=self.config.default_query_name,
                qtype=self.config.default_query_type
            )
            base_query.qclass = self.config.default_query_class
            
            # Apply mutations
            try:
                mutated_query = self.mutator.mutate(base_query)
                
                # Check if mutation was actually applied
                if mutated_query != base_query:
                    self.stats['mutations_applied'] += 1
                
                # Generate queries for target servers
                if self.config.test_all_servers:
                    # Send to all servers
                    for server_idx, target_server in enumerate(self.config.target_servers):
                        query_data = {
                            'iteration': iteration,
                            'server_index': server_idx,
                            'target_server': target_server,
                            'target_port': self.config.target_port,
                            'original_query': base_query,
                            'mutated_query': mutated_query,
                            'timestamp': time.time()
                        }
                        yield query_data
                else:
                    # Original behavior: select one server randomly
                    target_server = random.choice(self.config.target_servers)
                    query_data = {
                        'iteration': iteration,
                        'server_index': 0,
                        'target_server': target_server,
                        'target_port': self.config.target_port,
                        'original_query': base_query,
                        'mutated_query': mutated_query,
                        'timestamp': time.time()
                    }
                    yield query_data
                
                iteration += 1
                
            except Exception as e:
                logger.error(f"Error generating query {iteration}: {e}")
                iteration += 1
                continue
    
    async def _send(self, semaphore: asyncio.Semaphore, query_data: Dict[str, Any]) -> None:
        """Send a single query with semaphore control."""
        async with semaphore:
            await self._send_query(query_data)
    
    async def _send_query(self, query_data: Dict[str, Any]) -> None:
        """Send a single DNS query and record the result."""
        iteration = query_data['iteration']
        server_index = query_data.get('server_index', 0)
        target_server = query_data['target_server']
        target_port = query_data['target_port']
        mutated_query = query_data['mutated_query']
        
        result = {
            'iteration': iteration,
            'server_index': server_index,
            'target_server': target_server,
            'target_port': target_port,
            'timestamp': query_data['timestamp'],
            'query_sent': None,
            'response_received': None,
            'response_time': None,
            'error': None,
            'timeout': False
        }
        
        try:
            # Convert query to wire format
            query_bytes = mutated_query.to_wire()
            result['query_sent'] = len(query_bytes)
            
            # Send query and measure response time
            start_time = time.time()
            response_bytes = await self._send_udp_query(
                query_bytes, target_server, target_port
            )
            end_time = time.time()
            
            result['response_time'] = end_time - start_time
            result['response_received'] = len(response_bytes) if response_bytes else 0
            
            # Parse response if received
            if response_bytes:
                try:
                    response_query = DNSQuery.from_wire(response_bytes)
                    if self.config.save_responses:
                        result['response_data'] = self._serialize_query(response_query)
                except Exception as e:
                    logger.debug(f"Failed to parse response for iteration {iteration}: {e}")
                    result['parse_error'] = str(e)
            
            # Save packet data if requested
            if self.config.save_packets:
                result['query_packet'] = query_bytes.hex()
                if response_bytes:
                    result['response_packet'] = response_bytes.hex()
            
            self.stats['queries_sent'] += 1
            if response_bytes:
                self.stats['responses_received'] += 1
                
        except asyncio.TimeoutError:
            result['timeout'] = True
            result['error'] = 'Timeout'
            self.stats['timeouts'] += 1
            logger.debug(f"Timeout for query {iteration} to {target_server}")
            
        except Exception as e:
            result['error'] = str(e)
            self.stats['errors_encountered'] += 1
            logger.debug(f"Error sending query {iteration} to {target_server}: {e}")
        
        # Store result
        self.results.append(result)
        
        # Log progress
        if iteration % 100 == 0:
            logger.info(f"Completed {iteration} queries")

    async def _send_custom_packet(self, semaphore: asyncio.Semaphore, query_data: Dict[str, Any]) -> None:
        """Send a custom packet (raw bytes) with semaphore control."""
        async with semaphore:
            await self._send_raw_packet(query_data)

    async def _send_raw_packet(self, query_data: Dict[str, Any]) -> None:
        """Send raw packet bytes and record the result."""
        iteration = query_data['iteration']
        server_index = query_data.get('server_index', 0)
        target_server = query_data['target_server']
        target_port = query_data['target_port']
        packet_bytes = query_data['raw_packet_bytes']
        query_target = query_data.get('query_target', 'custom:unknown')

        result = {
            'iteration': iteration,
            'server_index': server_index,
            'target_server': target_server,
            'target_port': target_port,
            'timestamp': query_data['timestamp'],
            'query_target': query_target,
            'query_sent': len(packet_bytes),
            'response_received': None,
            'response_time': None,
            'error': None,
            'timeout': False,
            'is_custom_packet': True
        }

        try:
            # Send raw packet bytes and measure response time
            start_time = time.time()
            response_bytes = await self._send_udp_query(
                packet_bytes, target_server, target_port
            )
            end_time = time.time()

            result['response_time'] = end_time - start_time
            result['response_received'] = len(response_bytes) if response_bytes else 0

            # Parse response if received
            if response_bytes:
                try:
                    response_query = DNSQuery.from_wire(response_bytes)
                    if self.config.save_responses:
                        result['response_data'] = self._serialize_query(response_query)
                except Exception as e:
                    logger.debug(f"Failed to parse response for custom packet {query_target}: {e}")
                    result['parse_error'] = str(e)

            # Save packet data if requested
            if self.config.save_packets:
                result['query_packet'] = packet_bytes.hex()
                if response_bytes:
                    result['response_packet'] = response_bytes.hex()

            self.stats['queries_sent'] += 1
            if response_bytes:
                self.stats['responses_received'] += 1

        except asyncio.TimeoutError:
            result['timeout'] = True
            result['error'] = 'Timeout'
            self.stats['timeouts'] += 1
            logger.debug(f"Timeout for custom packet {query_target} to {target_server}")

        except Exception as e:
            result['error'] = str(e)
            self.stats['errors_encountered'] += 1
            logger.debug(f"Error sending custom packet {query_target} to {target_server}: {e}")

        # Store result
        self.results.append(result)
    
    async def _send_udp_query(self, query_bytes: bytes, server: str, port: int) -> Optional[bytes]:
        """Send UDP DNS query and return response using async operations."""
        try:
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                await loop.sock_sendto(sock, query_bytes, (server, port))
                response_data = await asyncio.wait_for(
                    loop.sock_recv(sock, 4096),
                    timeout=self.config.timeout
                )
                return response_data
            finally:
                sock.close()
                
        except asyncio.TimeoutError:
            raise asyncio.TimeoutError()
        except Exception as e:
            raise e
    
    def _serialize_query(self, query: DNSQuery) -> Dict[str, Any]:
        """Serialize DNSQuery to dictionary for JSON storage."""
        try:
            # Convert dataclass to dict, handling special types
            query_dict = asdict(query)
            
            # Convert enum values to strings
            if hasattr(query_dict['opcode'], 'name'):
                query_dict['opcode'] = query_dict['opcode'].name
            if hasattr(query_dict['response_code'], 'name'):
                query_dict['response_code'] = query_dict['response_code'].name
                
            return query_dict
        except Exception as e:
            logger.warning(f"Failed to serialize query: {e}")
            return {'error': f'Serialization failed: {e}'}
    
    async def _save_results(self) -> None:
        """Save fuzzing results to files."""
        output_path = Path(self.config.output_directory)
        
        # Save detailed results
        results_file = output_path / f"fuzzing_results_{int(time.time())}.json"
        try:
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'config': self.config.model_dump(),
                    'stats': self.stats,
                    'results': self.results
                }, f, indent=2, default=str)
            logger.info(f"Results saved to {results_file}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
        
        # Save summary statistics
        stats_file = output_path / f"fuzzing_stats_{int(time.time())}.json"
        try:
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.stats, f, indent=2, default=str)
            logger.info(f"Statistics saved to {stats_file}")
        except Exception as e:
            logger.error(f"Failed to save statistics: {e}")
    
    def _print_summary(self) -> None:
        """Print fuzzing summary."""
        duration = self.stats['end_time'] - self.stats['start_time']
        
        logger.info("=== Fuzzing Summary ===")
        logger.info(f"Duration: {duration:.2f} seconds")
        logger.info(f"Queries sent: {self.stats['queries_sent']}")
        logger.info(f"Responses received: {self.stats['responses_received']}")
        logger.info(f"Timeouts: {self.stats['timeouts']}")
        logger.info(f"Errors: {self.stats['errors_encountered']}")
        
        if self.stats['queries_sent'] > 0:
            response_rate = (self.stats['responses_received'] / self.stats['queries_sent']) * 100
            logger.info(f"Response rate: {response_rate:.1f}%")
            
            queries_per_second = self.stats['queries_sent'] / duration
            logger.info(f"Queries per second: {queries_per_second:.1f}")
        
        logger.info("======================")
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Get fuzzing results."""
        return self.results.copy()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get fuzzing statistics."""
        return self.stats.copy()

async def run_client(config: ClientConfig, **kwargs) -> DNSFuzzerClient:
    """Run the DNS client fuzzer with the given configuration.
    
    Args:
        config: ClientConfig instance
        
    Returns:
        DNSFuzzerClient instance with results
    """    
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)

    # Create and run client
    client = DNSFuzzerClient(config)
    await client.start_fuzzing()
    
    return client


if __name__ == "__main__":
    import sys
    
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    
    # Run the client fuzzer
    asyncio.run(run_client(config_path))