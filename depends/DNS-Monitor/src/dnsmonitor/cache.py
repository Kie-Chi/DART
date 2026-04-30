"""DNS Cache Monitor - Monitors DNS server cache changes for BIND and Unbound
"""

from concurrent.futures import thread
import time
import threading
import subprocess
import json
import socket
import re
import sys
import queue
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, NamedTuple, Set, Tuple, override
from dataclasses import dataclass, asdict, field
from pathlib import Path
import socketserver
try:
    from dns import name as dns_name, rdatatype, rdata, exception as dns_exception
except ImportError:
    print("Error: dnspython library not found. Please install it using: pip install dnspython")
    sys.exit(1)

from .traffic import create_resolver_monitor
from .packet import DNSPacket
from .config import CacheConfig, TrafficConfig
from .utils.logger import get_logger
from .utils import Colors, colorize
from .utils.common import get_timestamp, save_json

class PendingQuery(NamedTuple):
    query: DNSPacket
    timestamp: float

@dataclass(slots=True)
class DNSCacheRecord:
    """Represents a DNS cache record"""
    name: str
    rtype: str
    rdata: str
    ttl: int
    is_neg: bool = False
    timestamp: float = field(default_factory=time.time)
    original_ttl: int = field(init=False)

    def __post_init__(self):
        self.original_ttl = self.ttl
    
    def __eq__(self, other):
        if not isinstance(other, DNSCacheRecord):
            return False
        return (self.name == other.name and 
                self.rtype == other.rtype and 
                self.rdata == other.rdata and
                self.is_neg == other.is_neg)
    
    def __hash__(self):
        return hash((self.name, self.rdata, self.rtype, self.is_neg))
    
    def __str__(self):
        _marker = "\\- " if self.is_neg else ""
        return f"{self.name} {self.ttl} IN {_marker}{self.rtype} {self.rdata}"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.original_ttl


class CacheSnapshot:
    """Represents a DNS cache snapshot"""
    
    def __init__(self, timestamp: float = None, trigger: Optional[DNSPacket] = None):
        self.timestamp = timestamp or time.time()
        self.trigger = trigger
        self.records: Dict[Tuple[str, str, str], DNSCacheRecord] = {}
    
    def add_record(self, record: DNSCacheRecord) -> None:
        key = (record.name, record.rtype, record.rdata)
        self.records[key] = record
    
    def record_cnts(self) -> int:
        return len(self.records)
    
    def record_grps(self) -> Dict[str, int]:
        type_counts = {}
        for record in self.records.values():
            type_counts[record.rtype] = type_counts.get(record.rtype, 0) + 1
        return type_counts
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'trigger': self.trigger.to_dict() if self.trigger else None,
            'record_cnts': self.record_cnts(),
            'record_grps': self.record_grps(),
            'records': [record.to_dict() for record in self.records.values()]
        }


class CacheDiff:
    """Represents differences between two cache snapshots"""
    
    def __init__(self, old_snapshot: CacheSnapshot, new_snapshot: CacheSnapshot):
        self.old_snapshot = old_snapshot
        self.new_snapshot = new_snapshot
        self.timestamp = time.time()
        
        self.added_records: List[DNSCacheRecord] = []
        self.removed_records: List[DNSCacheRecord] = []
        self.modified_records: List[Dict[str, Any]] = []
        
        self._calculate_diff()
    
    def _calculate_diff(self) -> None:
        old_records_set = set(self.old_snapshot.records.values())
        new_records_set = set(self.new_snapshot.records.values())
        
        self.added_records = list(new_records_set - old_records_set)
        self.removed_records = list(old_records_set - new_records_set)
        
        old_map = {hash(r): r for r in old_records_set}
        new_map = {hash(r): r for r in new_records_set}

        common_keys = set(old_map.keys()) & set(new_map.keys())
        added_pkts = []
        removed_pkts = []
        _escape_time = self.new_snapshot.timestamp - self.old_snapshot.timestamp
        _eps = 1.5
        for key in common_keys:
            old_rec = old_map[key]
            new_rec = new_map[key]
            # These records in negative cache have no TTL in BIND dump format
            if old_rec.is_neg:
                continue

            # If TTL has decreased, it's a modification
            _ideal = old_rec.ttl - _escape_time
            if new_rec.ttl >= _ideal + _eps:
                self.modified_records.append({
                    'old': old_rec.to_dict(),
                    'new': new_rec.to_dict(),
                    'ideal': _ideal,
                    'actual': new_rec.ttl,
                })
                added_pkts.append(new_rec)
                removed_pkts.append(old_rec)
        if added_pkts:
            self.added_records = [rec for rec in self.added_records if rec not in added_pkts]
        if removed_pkts:
            self.removed_records = [rec for rec in self.removed_records if rec not in removed_pkts]

    def has_changes(self) -> bool:
        return bool(self.added_records or self.removed_records or self.modified_records)
    
    def get_summary(self) -> Dict[str, int]:
        return {
            'added': len(self.added_records),
            'removed': len(self.removed_records),
            'modified': len(self.modified_records)
        }
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'old_snap_time': self.old_snapshot.timestamp,
            'new_snap_time': self.new_snapshot.timestamp,
            'trigger': self.new_snapshot.trigger.to_dict() if self.new_snapshot.trigger else None,
            'summary': self.get_summary(),
            'added': [r.to_dict() for r in self.added_records],
            'removed': [r.to_dict() for r in self.removed_records],
            'modified': self.modified_records
        }


class AbstractCacheMonitor(ABC):
    def __init__(self, config: CacheConfig):
        self.config = config
        self.logger = get_logger(__name__)

    @abstractmethod
    def dump_cache(self) -> str: pass

    @abstractmethod
    def parse_cache(self, cache_content: str, trigger: Optional[DNSPacket]) -> CacheSnapshot: pass

class BindCacheMonitor(AbstractCacheMonitor):
    def __init__(self, config: CacheConfig):
        super().__init__(config)
        self.rndc_key_file = config.bind.rndc_key_file
        self.dump_file = config.bind.dump_file
    
    def dump_cache(self) -> str:
        # Simplified dump logic for brevity, original logic is also fine
        try:
            cmd = ["rndc", "-s", self.config.common.resolver_ip, "-k", self.rndc_key_file, "dumpdb", "-cache"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.logger.error(f"rndc dump failed: {result.stderr}")
                return ""
            
            time.sleep(0.1)
            with open(self.dump_file, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Failed to dump BIND cache: {e}")
            return ""

    def parse_cache(self, cache_data: str, trigger: Optional[DNSPacket]) -> CacheSnapshot:
        snapshot = CacheSnapshot(trigger=trigger)
        self.logger.debug("Starting standard parse of BIND cache dump.")

        view = None
        status = None
        source_type = None
        domain = ""
        current_rrset = None  # Buffer for accumulating multi-line records

        lines = cache_data.split('\n')
        for line in lines:
            line = line.strip('\n')
            if not line:
                continue
            
            # Flush buffered record if the new line is NOT a continuation line
            if current_rrset and not line.startswith('\t\t\t\t\t'):
                self._add_parsed_record(snapshot, current_rrset)
                current_rrset = None

            if line == ';':
                pass
            elif line[:12] == '; Start view':
                view = line[13:]
            elif line[:12] == '; Cache dump':
                status = 'cache'
            elif line[:23] == '; Address database dump':
                status = 'address'
            elif line[:22] == '; Unassociated entries':
                status = 'unassociated'
            elif line[:11] == '; Bad cache':
                status = 'bad_cache'
            elif line[:16] == '; SERVFAIL cache':
                status = 'servfail_cache'
            elif line[:9] == '; using a':
                pass
            elif line[:15] == '; Dump complete':
                break
            elif line[:5] == '$DATE':
                pass
            elif line[0] == ';':
                tmp = line.split(' ', 3)
                if len(tmp) < 3:
                    source_type = tmp[1] if len(tmp) > 1 else None
                else:
                    if status == 'cache':
                        # Parse NSEC/NSEC3/SOA hidden in negative cache comments
                        name, rrset = self._parse_neg_comment(line)
                        if rrset:
                            current_rrset = rrset
            elif status == 'cache':
                if line[:5] == '\t\t\t\t\t':
                    # Continuation line - cleanly append to the buffer
                    if current_rrset:
                        current_rrset['rdata'] += " " + line.strip()
                else:
                    if line[0] == '\t':
                        name, rrset = self._parse_rrset(line, domain_name=domain, source_type=source_type, view=view)
                    else:
                        name, rrset = self._parse_rrset(line, domain_name=None, source_type=source_type, view=view)
                        domain = name
                    
                    if rrset:
                        current_rrset = rrset

        # Flush the final record in the buffer when the loop ends
        if current_rrset:
            self._add_parsed_record(snapshot, current_rrset)

        self.logger.info(f"Parsed {snapshot.record_cnts()} records from BIND cache.")
        return snapshot

    def _parse_neg_comment(self, record_str: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Robust parser for SOA, NSEC, and NSEC3 records in negative cache comments."""
        clean_str = record_str.lstrip('; \t')
        parts = clean_str.split()
        if len(parts) < 3:
            return '', None
            
        try:
            rrset = {
                'name': parts[0],
                'ttl': '0',  # BIND omits TTL in these comment lines
                'is_neg': True
            }
            if parts[1] == 'IN':
                rrset['type'] = parts[2]
                rrset['rdata'] = " ".join(parts[3:])
            else:
                rrset['type'] = parts[1]
                rrset['rdata'] = " ".join(parts[2:])
                
            return rrset['name'], rrset
        except IndexError:
            return '', None

    def _add_parsed_record(self, snapshot: CacheSnapshot, rrset: Dict[str, Any]) -> None:
        """Convert parsed rrset dict to DNSCacheRecord and add to snapshot"""
        try:
            name = rrset.get('name', '')
            ttl_str = rrset.get('ttl', '0')
            rtype = rrset.get('type', '')
            rdata_str = rrset.get('rdata', '')
            is_neg = rrset.get('is_neg', False)

            # Strip BIND's negative cache prefixes (e.g., \-NS or -NS) so dnspython can parse the type
            if rtype.startswith('\\-'):
                rtype = rtype[2:]
                is_neg = True
            elif rtype.startswith('-'):
                rtype = rtype[1:]
                is_neg = True

            ttl = int(ttl_str) if ttl_str.isdigit() else 0

            # Normalize using dnspython
            domain_obj = dns_name.from_text(name)
            rdtype_obj = rdatatype.from_text(rtype)

            try:
                # By passing the buffered string as a whole, dnspython handles the ( ) perfectly
                rdata_obj = rdata.from_text(1, rdtype_obj, rdata_str, origin=domain_obj)
                normalized_rdata = rdata_obj.to_text()
            except dns_exception.DNSException:
                normalized_rdata = rdata_str

            record = DNSCacheRecord(
                name=domain_obj.to_text(omit_final_dot=True),
                rtype=rdatatype.to_text(rdtype_obj),
                rdata=normalized_rdata,
                ttl=ttl,
                is_neg=is_neg
            )
            snapshot.add_record(record)
        except Exception as e:
            self.logger.debug(f"Skipping record due to parsing error: {rrset}. Error: {e}")

    def _parse_soa(self, record_str: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Robust SOA comment parsing"""
        clean_str = record_str.lstrip('; \t')
        
        parts = clean_str.split()
        if len(parts) < 5:
            return '', None
            
        try:
            rrset = {
                'name': parts[0],
                'ttl': parts[1]
            }
            if parts[2] == 'IN':
                rrset['type'] = parts[3]
                rrset['rdata'] = " ".join(parts[4:])
            else:
                rrset['type'] = parts[2]
                rrset['rdata'] = " ".join(parts[3:])
                
            return rrset['name'], rrset
        except IndexError:
            return '', None

    def _parse_rrset(self, record_str: str, domain_name: Optional[str] = None,
                     source_type: Optional[str] = None, view: Optional[str] = None) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Robust RRset parsing for BIND cache dumps"""
        rrset = {'source_type': source_type, 'view': view}
        parts = record_str.split()
        if not parts:
            return '', None
        if domain_name:
            rrset['name'] = domain_name
            offset = 0
        else:
            rrset['name'] = parts[0]
            offset = 1

        try:
            rrset['ttl'] = parts[offset]
            if parts[offset+1] == 'IN':
                rrset['type'] = parts[offset+2]
                rrset['rdata'] = " ".join(parts[offset+3:])
            else:
                rrset['type'] = parts[offset+1]
                rrset['rdata'] = " ".join(parts[offset+2:])
        except IndexError:
            return '', None

        return rrset['name'], rrset

class UnboundCacheMonitor(AbstractCacheMonitor):
    def dump_cache(self) -> str:
        try:
            cmd = ["unbound-control", "dump_cache"]
            if self.config.unbound.control_config:
                cmd = ["unbound-control", "-s", self.config.common.resolver_ip, "-c", self.config.unbound.control_config, "dump_cache"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.logger.error(f"unbound-control dump failed: {result.stderr}")
                return ""
            return result.stdout
        except Exception as e:
            self.logger.error(f"Failed to dump Unbound cache: {e}")
            return ""
    
    def parse_cache(self, cache_data: str, trigger: Optional[DNSPacket]) -> CacheSnapshot:
        """
        Parse Unbound cache dump content into a CacheSnapshot.
        Uses standard parsing logic consistent with unbound_parser.py.
        """
        snapshot = CacheSnapshot(trigger=trigger)
        self.logger.debug("Starting standard parse of Unbound cache dump.")

        cache = []  # Parsed RRset entries
        msg = []    # Parsed Message entries
        status = None
        current_rrset_header = None

        for line in cache_data.splitlines():
            line = line.strip('\n')
            if line == 'START_RRSET_CACHE':
                status = 'RRSET_CACHE'
            elif line == 'START_MSG_CACHE':
                status = 'MSG_CACHE'
            elif line in ['END_RRSET_CACHE', 'END_MSG_CACHE']:
                status = None
            elif line == 'EOF':
                break
            elif status == 'RRSET_CACHE':
                if line[0] == ';':
                    # RRset header line (standard parse_rrset logic)
                    current_rrset_header = self._unbound_parse_rrset_header(line)
                    if current_rrset_header:
                        cache.append(current_rrset_header)
                else:
                    # Record line within RRset
                    if current_rrset_header:
                        record = self._unbound_parse_rrset_record(line)
                        if record:
                            current_rrset_header['records'].append(record)
            elif status == 'MSG_CACHE':
                if line[:3] == 'msg':
                    # Message header (standard parse_msg logic)
                    msg_header = self._unbound_parse_msg_header(line)
                    if msg_header:
                        msg.append(msg_header)
                else:
                    # Message reference line
                    if msg:
                        ref = self._unbound_parse_msg_reference(line)
                        msg[-1]['records'].append(ref)

        # Convert parsed cache to DNSCacheRecords (standard convert_cache logic)
        self._unbound_convert_to_snapshot(cache, snapshot)

        self.logger.info(f"Parsed {snapshot.record_cnts()} records from Unbound cache.")
        return snapshot

    def _unbound_parse_rrset_header(self, rrset_str: str) -> Optional[Dict[str, Any]]:
        """Standard RRset header parsing from unbound_parser.py"""
        if rrset_str[0] != ';':
            return None
        target = {'res_type': 'rrset'}
        rrset = rrset_str.split(' ')
        target['ttl'] = rrset[1]
        target['rr_count'] = rrset[2]
        target['rrsig_count'] = rrset[3]
        target['trust'] = rrset[4]
        target['security'] = rrset[5]
        target['records'] = []
        return target

    def _unbound_parse_rrset_record(self, rrset_str: str) -> Optional[Dict[str, Any]]:
        """Standard RRset record parsing from unbound_parser.py"""
        rrset = rrset_str.split('\t')
        if len(rrset) >= 5:
            return {'name': rrset[0], 'ttl': rrset[1], 'class': rrset[2],
                    'type': rrset[3], 'rdata': rrset[4]}
        return None

    def _unbound_parse_msg_header(self, msg_str: str) -> Optional[Dict[str, Any]]:
        """Standard Message header parsing from unbound_parser.py"""
        if msg_str[:3] != 'msg':
            return None
        msg = {'res_type': 'msg'}
        msgset = msg_str.split(' ')
        msg['name'] = msgset[1]
        msg['class'] = msgset[2]
        msg['type'] = msgset[3]
        msg['flags'] = msgset[4]
        msg['qdcount'] = msgset[5]
        msg['ttl'] = msgset[6]
        msg['security'] = msgset[7]
        msg['an'] = msgset[8]
        msg['ns'] = msgset[9]
        msg['ar'] = msgset[10]
        msg['records'] = []
        return msg

    def _unbound_parse_msg_reference(self, msg_str: str) -> Dict[str, Any]:
        """Standard Message reference parsing from unbound_parser.py"""
        msg = {}
        msgset = msg_str.split(' ')
        msg['name'] = msgset[0]
        msg['class'] = msgset[1]
        msg['type'] = msgset[2]
        msg['flags'] = msgset[3]
        return msg

    def _unbound_convert_to_snapshot(self, cache: List[Dict[str, Any]],
                                      snapshot: CacheSnapshot) -> None:
        """Convert parsed Unbound cache to DNSCacheRecords in snapshot.
        Based on convert_cache from unbound_parser.py.
        """
        for entry in cache:
            if entry['records']:
                for record in entry['records']:
                    try:
                        name = record['name']
                        ttl_str = record['ttl']
                        rclass = record['class']
                        rtype = record['type']
                        rdata_str = record['rdata']

                        ttl = int(ttl_str)

                        # Normalize using dnspython
                        domain_obj = dns_name.from_text(name)
                        rdtype_obj = rdatatype.from_text(rtype)

                        try:
                            rdata_obj = rdata.from_text(1, rdtype_obj, rdata_str, origin=domain_obj)
                            normalized_rdata = rdata_obj.to_text()
                        except dns_exception.DNSException:
                            normalized_rdata = rdata_str

                        cache_record = DNSCacheRecord(
                            name=domain_obj.to_text(omit_final_dot=True),
                            rtype=rdatatype.to_text(rdtype_obj),
                            rdata=normalized_rdata,
                            ttl=ttl,
                            is_neg=False
                        )
                        snapshot.add_record(cache_record)
                    except Exception as e:
                        self.logger.debug(f"Skipping record due to error: {record}. Error: {e}")

class CacheAnalysisServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass, monitor: 'CacheMonitor') -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.monitor = monitor

class CacheRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        response = {}
        try:
            with self.server.monitor.lock:
                latest_diff = self.server.monitor.last_diff
                latest_snapshot = self.server.monitor.current_snapshot
            
            if latest_diff:
                response = {
                    "status": "success",
                    "message": "Cache diff available.",
                    "diff": latest_diff.to_dict()
                }
            elif latest_snapshot:
                response = {
                    "status": "success",
                    "message": "No changes since last trigger.",
                    "snapshot": latest_snapshot.to_dict()
                }
            else:
                response = {
                    "status": "error",
                    "message": "No snapshot available yet."
                }
        except Exception as e:
            self.server.monitor.logger.error(f"Error handling client request: {e}")
            response = {
                "status": "error",
                "message": f"Failed to process request: {str(e)}"
            }
        finally:
            try:
                self.request.sendall(json.dumps(response, indent=2).encode('utf-8'))
            except Exception as send_err:
                self.server.monitor.logger.error(f"Failed to send response: {send_err}")


class CacheMonitor:
    def __init__(self, config: CacheConfig):
        resolver_ip = config.common.resolver_ip
        if not resolver_ip:
            raise ValueError("resolver_ip must be set for transaction-aware monitoring.")

        self.config = config
        self.logger = get_logger(__name__)
        self.running = threading.Event()
        self.lock = threading.Lock()
        
        self.cache_impl = self._cache_impl(config)
        # Data storage, protected by the lock
        self.current_snapshot: Optional[CacheSnapshot] = None
        self.last_diff: Optional[CacheDiff] = None
        
        self.pd_query: Dict[Tuple[str, int, int], PendingQuery] = {}
        self.trans_lock = threading.Lock()
        self.TRANSACTION_TIMEOUT = config.common.timeout # 2 seconds

        # Traffic monitoring setup
        self.packet_queue = queue.Queue(maxsize=10000)
        self.trigger_queue = queue.Queue(maxsize=100)
        bpf_filter = f"host {resolver_ip} and udp port 53"
        traffic_cfg = TrafficConfig(interface=config.common.interface, bpf_filter=bpf_filter)
        self.traffic_monitor = create_resolver_monitor(traffic_cfg, self._enqueue_packet)
        self.process_thread: Optional[threading.Thread] = None
        self.monitor_thread: Optional[threading.Thread] = None
        self.cleanup_thread: Optional[threading.Thread] = None
        
        # Analysis server
        self.analysis_server = self._setup_server()

    def _cache_impl(self, config: CacheConfig) -> AbstractCacheMonitor:
        """Reflectively get cache monitor implementation"""
        server_type = config.server_type.lower()
        impl_class_name = f"{server_type.capitalize()}CacheMonitor"
        current_module = sys.modules[__name__]
        if hasattr(current_module, impl_class_name):
            impl_class = getattr(current_module, impl_class_name)
            if issubclass(impl_class, AbstractCacheMonitor):
                self.logger.debug(f"Using {impl_class_name} for {config.server_type} cache monitoring")
                return impl_class(config)
        raise ValueError(f"Unsupported DNS server type: {config.server_type}")
        

    # Initialization and thread management methods
    def _setup_server(self):
        if self.config.common.enale_server:
            addr = (self.config.common.analysis_address, self.config.common.analysis_port)
            return CacheAnalysisServer(addr, CacheRequestHandler, self)
        return None

    def start(self):
        self.logger.info(f"Starting {self.config.server_type} cache monitoring...")
        self.running.set()

        self.logger.info("Taking initial cache snapshot...")
        self.current_snapshot = self._take_snapshot(None)

        self.process_thread = threading.Thread(target=self._process_worker, daemon=True)
        self.process_thread.start()

        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()

        self.cleanup_thread = threading.Thread(target=self._cleanup_pd_query, daemon=True)
        self.cleanup_thread.start()

        if self.analysis_server:
            threading.Thread(target=self.analysis_server.serve_forever, daemon=True).start()

        self.logger.info(f"Listening for DNS traffic involving {self.config.common.resolver_ip}...")
        self.traffic_monitor.start()

    def stop(self):
        self.logger.info("Stopping cache monitoring...")
        self.running.clear()
        self.traffic_monitor.stop()

        if self.analysis_server:
            self.analysis_server.shutdown()
        
        self.trigger_queue.put(None) # Sentinel for monitor_thread
        if self.process_thread and self.process_thread.is_alive(): 
            self.process_thread.join(timeout=2)
        if self.monitor_thread and self.monitor_thread.is_alive(): 
            self.monitor_thread.join(timeout=2)
        if self.cleanup_thread and self.cleanup_thread.is_alive(): 
            self.cleanup_thread.join(timeout=2)
        
        self.logger.info("Cache monitoring stopped.")
    
    def _enqueue_packet(self, packet: DNSPacket):
        """Keep it fast."""
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            self.logger.warning("Packet queue is full, dropped.")

    def _process_worker(self):
        """Continuously processes packets from the packet_queue."""
        self.logger.debug("Packet processing worker started.")
        while self.running.is_set():
            try:
                packet = self.packet_queue.get(timeout=1.0)
                if packet is None: # Sentinel
                    break
                self._process_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in packet processing worker: {e}", exc_info=True)
        self.logger.debug("Packet processing worker stopped.")

    def _process_packet(self, packet: DNSPacket):
        resolver_ip = self.config.common.resolver_ip
        
        with self.trans_lock:
            if not packet.is_response and packet.dst_ip == resolver_ip:
                key = (packet.src_ip, packet.src_port, packet.query_id)
                self.pd_query[key] = PendingQuery(query=packet, timestamp=time.time())
                self.logger.debug(f"Tracking new query: {packet.qname} from {packet.src_ip}:{packet.src_port}")

            elif packet.is_response and packet.src_ip == resolver_ip:
                key = (packet.dst_ip, packet.dst_port, packet.query_id)
                if key in self.pd_query:
                    pending = self.pd_query.pop(key)
                    self.logger.debug(f"Matched response for: {pending.query.qname}")
                    try:
                        self.trigger_queue.put_nowait(packet)
                    except queue.Full:
                        self.logger.warning("Trigger queue full, dropping transaction completion trigger.")

    def _cleanup_pd_query(self):
        while self.running.is_set():
            time.sleep(self.TRANSACTION_TIMEOUT)
            with self.trans_lock:
                now = time.time()
                expired_keys = [
                    key for key, trans in self.pd_query.items()
                    if now - trans.timestamp > self.TRANSACTION_TIMEOUT
                ]
                for key in expired_keys:
                    trans = self.pd_query.pop(key)
                    self.logger.debug(f"Timing out tracked query for {trans.query.qname}")

    def _monitoring_loop(self):
        last_dump_time = 0.0
        while self.running.is_set():
            try:
                trigger = self.trigger_queue.get(timeout=1.0)
                if trigger is None: 
                    break

                if time.time() - last_dump_time < self.config.common.cooldown_period:
                    continue

                self.logger.info(f"Transaction for '{trigger.qname}' completed. Triggering cache dump.")
                
                new_snapshot = self._take_snapshot(trigger)
                last_dump_time = time.time()
                
                with self.lock:
                    if new_snapshot and self.current_snapshot:
                        diff = CacheDiff(self.current_snapshot, new_snapshot)
                        if diff.has_changes():
                            self.last_diff = diff
                            self.print(diff)
                        else:
                            self.last_diff = None
                            self.logger.info("No cache changes detected.")
                    self.current_snapshot = new_snapshot

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}", exc_info=True)

    def _take_snapshot(self, trigger: Optional[DNSPacket]) -> Optional[CacheSnapshot]:
        try:
            cache_data = self.cache_impl.dump_cache()
            if cache_data:
                return self.cache_impl.parse_cache(cache_data, trigger)
            return None
        except Exception as e:
            self.logger.error(f"Failed to take cache snapshot: {e}")
            return None

    def print(self, diff: CacheDiff):
        summary = diff.get_summary()
        self.logger.info(
            f"{colorize('CACHE CHANGES DETECTED', Colors.CYAN)}: "
            f"+{summary['added']} added, -{summary['removed']} removed, ~{summary['modified']} modified TTL"
        )
        for record in diff.added_records[:5]:
            self.logger.info(f"  {colorize('+', Colors.GREEN)} {record}")
        
        if self.config.common.save_changes:
            self._save_cache_changes(diff)

    def _save_cache_changes(self, diff: CacheDiff):
        try:
            timestamp = get_timestamp()
            path = Path(self.config.common.cache_changes_dir)
            path.mkdir(parents=True, exist_ok=True)
            filename = path / f"cache_diff_{timestamp}.json"
            save_json(diff.to_dict(), str(filename))
            self.logger.debug(f"Cache changes saved to: {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save cache changes: {e}")