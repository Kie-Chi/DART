"""
Lightweight DNS Packet implementation with lazy loading
"""

import socket
import time
from typing import Optional, List, Dict, Any, Union, Iterator
from dataclasses import dataclass, field
import dpkt
from dnslib import DNSRecord, DNSQuestion, RR, QTYPE, RCODE

# --- Packet ---
DNS_TYPE_MAP = {
    1: "A", 
    2: "NS", 
    5: "CNAME", 
    6: "SOA", 
    12: "PTR", 
    15: "MX", 
    16: "TXT", 
    28: "AAAA",
    41: "OPT", 
    43: "DS", 
    46: "RRSIG", 
    47: "NSEC", 
    48: "DNSKEY", 
    50: "NSEC3",
    51: "NSEC3PARAM", 
    52: "TLSA", 
    257: "CAA", 
    32768: "TA", 
    32769: "DLV"
}
RCODE_MAP = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"
}
DNS_PORT = 53


# A type alias for DNSPacket
Packet = 'DNSPacket'

@dataclass(slots=True)
class DNSPacket:
    """DNS packet object with lazy loading"""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "UDP" or "TCP"

    # DNS-specific fields
    query_id: int
    is_response: bool
    flags: int

    # lazy-loaded fields
    _raw_packet: bytes = field(repr=False)
    _dns_data: bytes = field(repr=False)

    # dnslib native object (cached for performance)
    _dnslib_record: Optional[DNSRecord] = field(default=None, init=False, repr=False)

    # Lightweight caches (only for frequently accessed data)
    _qname_cache: Optional[str] = field(default=None, init=False, repr=False)
    _qtype_cache: Optional[str] = field(default=None, init=False, repr=False)

    # Cache for parsed RR lists (to avoid re-parsing)
    _answers_cache: Optional[List[Dict[str, Any]]] = field(default=None, init=False, repr=False)
    _authorities_cache: Optional[List[Dict[str, Any]]] = field(default=None, init=False, repr=False)
    _additionals_cache: Optional[List[Dict[str, Any]]] = field(default=None, init=False, repr=False)

    def _format_name(self, name: str) -> str:
        """Format domain name, handling root domain correctly."""
        if not name:
            return "."
        # dnslib returns names with trailing dot, which is fine
        return name

    @property
    def dnslib_record(self) -> Optional[DNSRecord]:
        """Get dnslib DNSRecord object (lazy loaded)"""
        if self._dnslib_record is None:
            try:
                self._dnslib_record = DNSRecord.parse(self._dns_data)
            except Exception as e:
                import sys
                print(f"[DEBUG] DNS parsing failed: {e}, data length: {len(self._dns_data)}", file=sys.stderr)
                return None
        return self._dnslib_record

    @property
    def qname(self) -> str:
        """Get query name (cached)"""
        if self._qname_cache is None:
            record = self.dnslib_record
            if record and record.q:
                try:
                    self._qname_cache = self._format_name(str(record.q.qname).rstrip('.'))
                except Exception:
                    self._qname_cache = ""
            else:
                self._qname_cache = ""
        return self._qname_cache

    @property
    def qtype(self) -> str:
        """Get query type (cached)"""
        if self._qtype_cache is None:
            record = self.dnslib_record
            if record and record.q:
                try:
                    self._qtype_cache = QTYPE.get(record.q.qtype, f"TYPE{record.q.qtype}")
                except Exception:
                    self._qtype_cache = ""
            else:
                self._qtype_cache = ""
        return self._qtype_cache

    @property
    def rcode(self) -> int:
        """Get response code"""
        record = self.dnslib_record
        if record:
            return record.header.rcode
        return 0

    @property
    def questions(self) -> Iterator[Any]:
        """Get questions iterator"""
        record = self.dnslib_record
        if record and record.q:
            yield record.q

    @property
    def answers(self) -> Iterator[Any]:
        """Get answers iterator"""
        record = self.dnslib_record
        if record and record.rr:
            yield from record.rr

    @property
    def authorities(self) -> Iterator[Any]:
        """Get authorities iterator"""
        record = self.dnslib_record
        if record and record.auth:
            yield from record.auth

    @property
    def additionals(self) -> Iterator[Any]:
        """Get additionals iterator"""
        record = self.dnslib_record
        if record and record.ar:
            yield from record.ar
    
    @property
    def raw_packet(self) -> bytes:
        """Get raw packet data"""
        return self._raw_packet

    def get_question_dict(self, q: Any) -> Dict[str, Any]:
        """Convert question to dictionary"""
        try:
            return {
                'name': self._format_name(str(q.qname).rstrip('.')),
                'type': QTYPE.get(q.qtype, f"TYPE{q.qtype}"),
                'class': q.qclass
            }
        except Exception:
            return {'name': '', 'type': '', 'class': 0}

    def get_rr_dict(self, rr: Any) -> Dict[str, Any]:
        """Convert resource record to dictionary using dnslib"""
        try:
            rr_type = QTYPE.get(rr.rtype, f"TYPE{rr.rtype}")

            # basic fields
            result = {
                'name': self._format_name(str(rr.rname).rstrip('.')),
                'type': rr_type,
                'class': rr.rclass,
                'ttl': rr.ttl,
                'rdata': {}
            }

            # parse rdata based on type
            try:
                rdata = rr.rdata

                # Handle OPT (EDNS0) specially
                if rr.rtype == 41:  # OPT
                    result['class'] = 0
                    result['ttl'] = 0
                    result['edns'] = {
                        'udp_payload_size': rr.rclass,
                        'ext_rcode': (rr.ttl >> 24) & 0xff,
                        'version': (rr.ttl >> 16) & 0xff,
                        'flags': rr.ttl & 0xffff,
                        'do_bit': bool(rr.ttl & 0x8000)
                    }
                    # dnslib OPT has options as a list
                    if hasattr(rdata, 'options') and rdata.options:
                        options_hex = ''.join(opt.to_hex() if hasattr(opt, 'to_hex') else str(opt) for opt in rdata.options)
                        result['rdata'] = {'options': options_hex}
                    else:
                        result['rdata'] = {'options': ""}

                elif rr.rtype == 1:  # A
                    result['rdata']['address'] = str(rdata)

                elif rr.rtype == 28:  # AAAA
                    result['rdata']['address'] = str(rdata)

                elif rr.rtype == 5:  # CNAME
                    result['rdata']['cname'] = self._format_name(str(rdata).rstrip('.'))

                elif rr.rtype == 15:  # MX
                    result['rdata'] = {
                        'preference': rdata.preference,
                        'exchange': self._format_name(str(rdata.label).rstrip('.'))
                    }

                elif rr.rtype == 2:  # NS
                    result['rdata']['nsname'] = self._format_name(str(rdata).rstrip('.'))

                elif rr.rtype == 12:  # PTR
                    result['rdata']['ptrname'] = self._format_name(str(rdata).rstrip('.'))

                elif rr.rtype == 6:  # SOA
                    result['rdata'] = {
                        'mname': self._format_name(str(rdata.mname).rstrip('.')),
                        'rname': self._format_name(str(rdata.rname).rstrip('.')),
                        'serial': rdata.times[0],
                        'refresh': rdata.times[1],
                        'retry': rdata.times[2],
                        'expire': rdata.times[3],
                        'minimum': rdata.times[4]
                    }

                elif rr.rtype == 16:  # TXT
                    # dnslib TXT rdata can be accessed via str() or .data
                    try:
                        if hasattr(rdata, 'data'):
                            txt_data = rdata.data
                            if isinstance(txt_data, bytes):
                                result['rdata']['text'] = txt_data.decode('utf-8', errors='replace')
                            elif isinstance(txt_data, list):
                                texts = []
                                for part in txt_data:
                                    if isinstance(part, bytes):
                                        texts.append(part.decode('utf-8', errors='replace'))
                                    else:
                                        texts.append(str(part))
                                result['rdata']['text'] = ''.join(texts)
                            else:
                                result['rdata']['text'] = str(txt_data)
                        else:
                            result['rdata']['text'] = str(rdata)
                    except Exception:
                        result['rdata']['text'] = str(rdata)

                elif rr.rtype == 43:  # DS
                    result['rdata'] = {
                        'key_tag': rdata.key_tag,
                        'algorithm': rdata.algorithm,
                        'digest_type': rdata.digest_type,
                        'digest': rdata.digest.hex() if isinstance(rdata.digest, bytes) else str(rdata.digest)
                    }

                elif rr.rtype == 48:  # DNSKEY
                    result['rdata'] = {
                        'flags': rdata.flags,
                        'protocol': rdata.protocol,
                        'algorithm': rdata.algorithm,
                        'key': rdata.key.hex() if isinstance(rdata.key, bytes) else str(rdata.key)
                    }

                elif rr.rtype == 46:  # RRSIG
                    result['rdata'] = {
                        'type_covered': rdata.covered,
                        'algorithm': rdata.algorithm,
                        'labels': rdata.labels,
                        'original_ttl': rdata.orig_ttl,
                        'signature_inception': rdata.sig_inc,
                        'signature_expiration': rdata.sig_exp,
                        'key_tag': rdata.key_tag,
                        'signer_name': self._format_name(str(rdata.name).rstrip('.')),
                        'signature': rdata.sig.hex() if isinstance(rdata.sig, bytes) else str(rdata.sig)
                    }

                elif rr.rtype == 47:  # NSEC
                    bitmap_data = getattr(rdata, 'bitmap', getattr(rdata, 'type_bitmap', b''))
                    result['rdata'] = {
                        'next_domain': self._format_name(str(getattr(rdata, 'next_domain', '')).rstrip('.')),
                        'type_bitmap': bitmap_data.hex() if isinstance(bitmap_data, bytes) else str(bitmap_data)
                    }

                elif rr.rtype == 50:  # NSEC3
                    bitmap_data = getattr(rdata, 'bitmap', getattr(rdata, 'type_bitmap', b''))
                    result['rdata'] = {
                        'hash_algorithm': getattr(rdata, 'hash_algorithm', 0),
                        'flags': getattr(rdata, 'flags', 0),
                        'iterations': getattr(rdata, 'iterations', 0),
                        'salt': getattr(rdata, 'salt', b'').hex() if isinstance(getattr(rdata, 'salt', b''), bytes) else str(getattr(rdata, 'salt', '')),
                        'next_hashed_owner': getattr(rdata, 'next_hashed_owner', b'').hex() if isinstance(getattr(rdata, 'next_hashed_owner', b''), bytes) else str(getattr(rdata, 'next_hashed_owner', '')),
                        'type_bitmap': bitmap_data.hex() if isinstance(bitmap_data, bytes) else str(bitmap_data)
                    }

                elif rr.rtype == 52:  # TLSA
                    result['rdata'] = {
                        'certificate_usage': rdata.certificate_usage,
                        'selector': rdata.selector,
                        'matching_type': rdata.matching_type,
                        'association_data': rdata.certificate_association_data.hex() if hasattr(rdata, 'certificate_association_data') and isinstance(rdata.certificate_association_data, bytes) else str(rdata)
                    }

                elif rr.rtype == 257:  # CAA
                    result['rdata'] = {
                        'flags': rdata.flags,
                        'tag': str(rdata.tag),
                        'value': str(rdata.value)
                    }

                else:
                    # For unknown types, try to get raw representation
                    result['rdata']['raw'] = str(rdata)

            except Exception as e:
                import sys
                print(f"[DEBUG] RR parse error: {e}, type={rr_type}", file=sys.stderr)
                result['rdata'] = {'raw': str(rr.rdata) if hasattr(rr, 'rdata') else ''}

            return result

        except Exception as e:
            import sys
            print(f"[DEBUG] RR dict error: {e}", file=sys.stderr)
            return {'name': '', 'type': '', 'class': 0, 'ttl': 0, 'rdata': {}}

    def get_questions_list(self) -> List[Dict[str, Any]]:
        """Get questions as list of dictionaries"""
        return [self.get_question_dict(q) for q in self.questions]

    def get_answers_list(self) -> List[Dict[str, Any]]:
        """Get answers as list of dictionaries (cached)"""
        if self._answers_cache is None:
            record = self.dnslib_record
            if record:
                import sys
                print(f"[DEBUG] DNS object - qr={record.header.qr}, opcode={record.header.opcode}, rcode={record.header.rcode}", file=sys.stderr)
                print(f"[DEBUG] Counts - qd={1 if record.q else 0}, an={len(record.rr) if record.rr else 0}, ns={len(record.auth) if record.auth else 0}, ar={len(record.ar) if record.ar else 0}", file=sys.stderr)
            self._answers_cache = [self.get_rr_dict(rr) for rr in self.answers]
        return self._answers_cache

    def get_authorities_list(self) -> List[Dict[str, Any]]:
        """Get authorities as list of dictionaries (cached)"""
        if self._authorities_cache is None:
            self._authorities_cache = [self.get_rr_dict(rr) for rr in self.authorities]
        return self._authorities_cache

    def get_additionals_list(self) -> List[Dict[str, Any]]:
        """Get additionals as list of dictionaries (cached)"""
        if self._additionals_cache is None:
            self._additionals_cache = [self.get_rr_dict(rr) for rr in self.additionals]
        return self._additionals_cache

    def _get_qtype_name(self, qtype: int) -> str:
        """Get DNS query type name - optimized version"""
        return DNS_TYPE_MAP.get(qtype, f"TYPE{qtype}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary"""
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'query_id': self.query_id,
            'is_response': self.is_response,
            'flags': self.flags,
            'qname': self.qname,
            'qtype': self.qtype,
            'rcode': self.rcode,
            'questions': self.get_questions_list(),
            'answers': self.get_answers_list(),
            'authorities': self.get_authorities_list(),
            'additionals': self.get_additionals_list()
        }

    def __str__(self) -> str:
        """String representation"""
        direction = "Response" if self.is_response else "Query"
        rcode_str = f" ({self._get_rcode_name(self.rcode)})" if self.is_response else ""
        return f"{self.timestamp:.6f} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} " \
               f"{self.protocol} DNS {direction} ID:{self.query_id} {self.qname} {self.qtype}{rcode_str}"

    def _get_rcode_name(self, rcode: int) -> str:
        """Get response code name - optimized version"""
        return RCODE_MAP.get(rcode, f"RCODE{rcode}")


class DNSAnalyzer:
    """Basic DNS analyzer using dpkt"""
    
    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'dns_packets': 0,
            'parse_errors': 0,
            'dpkt_unpack_calls': 0
        }
    
    def analyze_packet(self, timestamp: float, packet_data: bytes) -> Optional[DNSPacket]:
        """Analyze packet using dpkt's efficient unpack methods"""
        try:
            self.stats['total_packets'] += 1
            try:
                eth = dpkt.ethernet.Ethernet(packet_data)
                self.stats['dpkt_unpack_calls'] += 1
            except (dpkt.UnpackError, dpkt.NeedData):
                return None
            if not isinstance(eth.data, dpkt.ip.IP):
                return None
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            dns_data = None
            protocol = None
            src_port = dst_port = 0
            
            if isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                if udp.sport != DNS_PORT and udp.dport != DNS_PORT:
                    return None
                src_port, dst_port = udp.sport, udp.dport
                protocol = "UDP"
                dns_data = udp.data
            elif isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                if tcp.sport != DNS_PORT and tcp.dport != DNS_PORT:
                    return None
                src_port, dst_port = tcp.sport, tcp.dport
                protocol = "TCP"
                if len(tcp.data) >= 2:
                    dns_data = tcp.data[2:]
                else:
                    return None
            else:
                return None
            
            if not dns_data or len(dns_data) < 12:
                return None
            
            try:
                dns_header = dpkt.dns.DNS(dns_data)
                self.stats['dpkt_unpack_calls'] += 1
            except (dpkt.UnpackError, dpkt.NeedData):
                return None
            
            query_id = dns_header.id
            flags = (dns_header.qr << 15) | (dns_header.opcode << 11) | \
                   (dns_header.aa << 10) | (dns_header.tc << 9) | \
                   (dns_header.rd << 8) | (dns_header.ra << 7) | dns_header.rcode
            is_response = dns_header.qr == 1
            
            self.stats['dns_packets'] += 1
            
            return DNSPacket(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                query_id=query_id,
                is_response=is_response,
                flags=flags,
                _raw_packet=packet_data,
                _dns_data=dns_data
            )
            
        except Exception:
            self.stats['parse_errors'] += 1
            return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        stats = self.stats.copy()
        if stats['total_packets'] > 0:
            stats['dns_packet_ratio'] = stats['dns_packets'] / stats['total_packets']
            stats['error_ratio'] = stats['parse_errors'] / stats['total_packets']
        return stats


class OptimizedDNSAnalyzer(DNSAnalyzer):
    """Optimized DNS analyzer with fast path and slow path"""
    
    def __init__(self):
        super().__init__()
        # Pre-allocate buffer for IP addresses
        self._ip_buffer = bytearray(4)
        self.stats.update({
            'fast_path_hits': 0,
            'slow_path_hits': 0,
            'header_parse_time': 0.0,
            'total_parse_time': 0.0
        })
    
    def analyze_packet(self, timestamp: float, packet_data: bytes) -> Optional[DNSPacket]:
        """Optimized packet analysis"""
        start_time = time.perf_counter()
        
        try:
            self.stats['total_packets'] += 1
            
            if len(packet_data) >= 42:
                try:
                    if packet_data[12:14] != b'\x08\x00':
                        return None
                    
                    if packet_data[23] != 17:
                        if packet_data[23] != 6:
                            return None
                        return self._parse_tcp_packet(timestamp, packet_data, start_time)
                    return self._parse_udp_packet_fast(timestamp, packet_data, start_time)
                    
                except Exception:
                    # parse error, pass
                    pass
            
            # dpkt slow path
            return self._parse_packet_slow(timestamp, packet_data, start_time)
            
        except Exception:
            self.stats['parse_errors'] += 1
            return None
        finally:
            self.stats['total_parse_time'] += time.perf_counter() - start_time
    
    def _parse_udp_packet_fast(self, timestamp: float, packet_data: bytes, start_time: float) -> Optional[DNSPacket]:
        """fast path for udp packet"""
        try:
            # extract ip addresses
            src_ip_bytes = packet_data[26:30]
            dst_ip_bytes = packet_data[30:34]
            
            # extract udp ports
            src_port = int.from_bytes(packet_data[34:36], 'big')
            dst_port = int.from_bytes(packet_data[36:38], 'big')
            
            # check if dns port
            if src_port != DNS_PORT and dst_port != DNS_PORT:
                return None
            
            # extract dns data
            udp_length = int.from_bytes(packet_data[38:40], 'big')
            dns_start = 42
            dns_data = packet_data[dns_start:dns_start + udp_length - 8]
            
            if len(dns_data) < 12:
                return None
            
            # fast parse dns header
            header_parse_start = time.perf_counter()
            query_id = int.from_bytes(dns_data[0:2], 'big')
            flags_raw = int.from_bytes(dns_data[2:4], 'big')
            is_response = (flags_raw & 0x8000) != 0
            
            self.stats['header_parse_time'] += time.perf_counter() - header_parse_start
            self.stats['fast_path_hits'] += 1
            self.stats['dns_packets'] += 1
            
            return DNSPacket(
                timestamp=timestamp,
                src_ip=socket.inet_ntoa(src_ip_bytes),
                dst_ip=socket.inet_ntoa(dst_ip_bytes),
                src_port=src_port,
                dst_port=dst_port,
                protocol="UDP",
                query_id=query_id,
                is_response=is_response,
                flags=flags_raw,
                _raw_packet=packet_data,
                _dns_data=dns_data
            )
            
        except Exception:
            # parse error, pass
            return self._parse_packet_slow(timestamp, packet_data, start_time)
    
    def _parse_tcp_packet(self, timestamp: float, packet_data: bytes, start_time: float) -> Optional[DNSPacket]:
        """TCP packet parse (usually less frequent, use slow path)"""
        return self._parse_packet_slow(timestamp, packet_data, start_time)
    
    def _parse_packet_slow(self, timestamp: float, packet_data: bytes, start_time: float) -> Optional[DNSPacket]:
        """slow path: complete dpkt parse"""
        self.stats['slow_path_hits'] += 1
        return super().analyze_packet(timestamp, packet_data)
    
    def get_stats(self) -> Dict[str, Any]:
        """get optimized analyzer stats"""
        stats = super().get_stats()
        
        # add performance stats
        if self.stats['total_packets'] > 0:
            stats.update({
                'fast_path_ratio': self.stats['fast_path_hits'] / self.stats['total_packets'],
                'slow_path_ratio': self.stats['slow_path_hits'] / self.stats['total_packets'],
                'avg_parse_time_us': (self.stats['total_parse_time'] * 1000000) / self.stats['total_packets'],
                'avg_header_parse_time_us': (self.stats['header_parse_time'] * 1000000) / max(1, self.stats['fast_path_hits'])
            })
        
        return stats