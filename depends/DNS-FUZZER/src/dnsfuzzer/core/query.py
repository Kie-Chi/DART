"""DNS Query module for generating and manipulating DNS packets."""

import random
from dataclasses import dataclass, field
from typing import Dict, List, Union, Any
from dns.opcode import Opcode as DNSOpcode
from dns.rcode import Rcode as DNSRcode
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rrset
import dns.flags

from ..utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class DNSQuery:
    """Represents a DNS query packet with all its components."""
    
    # Header fields
    query_id: int = field(default_factory=lambda: random.randint(0, 65535))
    opcode: DNSOpcode = DNSOpcode.QUERY
    authoritative: bool = False
    truncated: bool = False
    recursion_desired: bool = True
    recursion_available: bool = False
    response_code: DNSRcode = DNSRcode.NOERROR
    is_response: bool = False
    
    # Question section
    qname: str = "example.com"
    qtype: str = "A"
    qclass: str = "IN"
    
    # Answer, Authority, Additional sections
    answers: List[Dict[str, Any]] = field(default_factory=list)
    authorities: List[Dict[str, Any]] = field(default_factory=list)
    additional: List[Dict[str, Any]] = field(default_factory=list)
    
    # EDNS options
    edns_version: int = 0
    edns_payload_size: int = 1232
    edns_dnssec_ok: bool = False
    edns_options: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dns_message(self) -> dns.message.Message:
        """Convert DNSQuery to dnspython Message object."""
        msg = dns.message.Message(id=self.query_id)
        
        # Set header flags
        msg.flags = 0
        if self.is_response:
            msg.flags |= dns.flags.QR
        if self.authoritative:
            msg.flags |= dns.flags.AA
        if self.truncated:
            msg.flags |= dns.flags.TC
        if self.recursion_desired:
            msg.flags |= dns.flags.RD
        if self.recursion_available:
            msg.flags |= dns.flags.RA
            
        # Set opcode and rcode
        msg.set_opcode(self.opcode.value)
        msg.set_rcode(self.response_code.value)
        
        # Add question
        qname_text = self.qname
        # Ensure qname is absolute
        if not qname_text.endswith('.'):
            qname_text += '.'
        qname = dns.name.from_text(qname_text)
        qtype = dns.rdatatype.from_text(self.qtype)
        qclass = dns.rdataclass.from_text(self.qclass)
        msg.question = [dns.rrset.RRset(qname, qclass, qtype)]
        
        # Add answer records
        for answer in self.answers:
            self._add_record_to_section(msg.answer, answer)
            
        # Add authority records
        for authority in self.authorities:
            self._add_record_to_section(msg.authority, authority)
            
        # Add additional records
        for additional_rec in self.additional:
            self._add_record_to_section(msg.additional, additional_rec)
            
        # Add EDNS if needed
        if self.edns_version >= 0:
            msg.use_edns(
                edns=self.edns_version,
                payload=self.edns_payload_size,
                options=self.edns_options
            )
            if self.edns_dnssec_ok:
                msg.flags |= dns.flags.DO
                
        return msg
    
    def _add_record_to_section(self, section: List, record_data: Dict[str, Any]) -> None:
        """Add a resource record to a message section."""
        try:
            name_text = record_data.get('name', self.qname)
            # Ensure name is absolute
            if not name_text.endswith('.'):
                name_text += '.'
            name = dns.name.from_text(name_text)
            rtype = dns.rdatatype.from_text(record_data.get('type', 'A'))
            rclass = dns.rdataclass.from_text(record_data.get('class', 'IN'))
            ttl = record_data.get('ttl', 300)
            rdata_text = record_data.get('rdata', '127.0.0.1')
            
            # For record types that contain domain names, ensure they are absolute
            if rtype in [dns.rdatatype.PTR, dns.rdatatype.CNAME, dns.rdatatype.NS, dns.rdatatype.MX]:
                # Check if rdata contains domain names that need to be absolute
                if isinstance(rdata_text, str) and not rdata_text.endswith('.') and not rdata_text.replace(' ', '').isdigit():
                    # For MX records, handle the priority prefix
                    if rtype == dns.rdatatype.MX and ' ' in rdata_text:
                        parts = rdata_text.split(' ', 1)
                        if len(parts) == 2 and parts[0].isdigit():
                            rdata_text = f"{parts[0]} {parts[1]}."
                    else:
                        rdata_text += '.'
            
            # Create rdata based on type
            rdata = dns.rdata.from_text(rclass, rtype, rdata_text)
            
            # Create RRset and add to section
            rrset = dns.rrset.RRset(name, rclass, rtype)
            rrset.add(rdata, ttl)
            section.append(rrset)
        except Exception as e:
            # Skip invalid records
            print(f"Warning: Failed to add record {record_data}: {e}")
    
    def to_wire(self) -> bytes:
        """Convert DNSQuery to wire format bytes."""
        msg = self.to_dns_message()
        return msg.to_wire()
    
    @classmethod
    def from_wire(cls, data: bytes) -> 'DNSQuery':
        """Create DNSQuery from wire format bytes."""
        msg = dns.message.from_wire(data)
        return cls.from_dns_message(msg)
    
    @classmethod
    def from_dns_message(cls, msg: dns.message.Message) -> 'DNSQuery':
        """Create DNSQuery from dnspython Message object."""
        query = cls()
        
        # Extract header information
        query.query_id = msg.id
        query.opcode = msg.opcode()
        query.authoritative = bool(msg.flags & dns.flags.AA)
        query.truncated = bool(msg.flags & dns.flags.TC)
        query.recursion_desired = bool(msg.flags & dns.flags.RD)
        query.recursion_available = bool(msg.flags & dns.flags.RA)
        query.response_code = msg.rcode()
        query.is_response = bool(msg.flags & dns.flags.QR)
        
        # Extract question
        if msg.question:
            q = msg.question[0]
            qname = str(q.name)
            if qname.endswith('.'):
                qname = qname[:-1]
            query.qname = qname
            query.qtype = dns.rdatatype.to_text(q.rdtype)
            query.qclass = dns.rdataclass.to_text(q.rdclass)
        
        # Extract sections
        query.answers = cls._extract_section(msg.answer)
        query.authorities = cls._extract_section(msg.authority)
        query.additional = cls._extract_section(msg.additional)
        
        # Extract EDNS information
        if msg.edns >= 0:
            query.edns_version = msg.edns
            query.edns_payload_size = msg.payload
            query.edns_dnssec_ok = bool(msg.flags & dns.flags.DO)
            query.edns_options = msg.options or []
        
        return query
    
    @staticmethod
    def _extract_section(section: List) -> List[Dict[str, Any]]:
        """Extract records from a message section."""
        records = []
        for rrset in section:
            for rdata in rrset:
                name = str(rrset.name)
                if name.endswith('.'):
                    name = name[:-1]
                records.append({
                    'name': name,
                    'type': dns.rdatatype.to_text(rrset.rdtype),
                    'class': dns.rdataclass.to_text(rrset.rdclass),
                    'ttl': rrset.ttl,
                    'rdata': str(rdata)
                })
        return records
    
    def clone(self) -> 'DNSQuery':
        """Create a deep copy of this DNSQuery."""
        return DNSQuery(
            query_id=self.query_id,
            opcode=self.opcode,
            authoritative=self.authoritative,
            truncated=self.truncated,
            recursion_desired=self.recursion_desired,
            recursion_available=self.recursion_available,
            response_code=self.response_code,
            is_response=self.is_response,
            qname=self.qname,
            qtype=self.qtype,
            qclass=self.qclass,
            answers=self.answers.copy(),
            authorities=self.authorities.copy(),
            additional=self.additional.copy(),
            edns_version=self.edns_version,
            edns_payload_size=self.edns_payload_size,
            edns_dnssec_ok=self.edns_dnssec_ok,
            edns_options=self.edns_options.copy()
        )


class DNSQueryBuilder:
    """Builder class for creating DNS queries with fluent interface."""
    
    def __init__(self):
        self._query = DNSQuery()
    
    def with_id(self, query_id: int) -> 'DNSQueryBuilder':
        """Set the query ID."""
        self._query.query_id = query_id
        return self
    
    def with_opcode(self, opcode: Union[DNSOpcode, int]) -> 'DNSQueryBuilder':
        """Set the opcode."""
        if isinstance(opcode, int):
            opcode = DNSOpcode(opcode)
        self._query.opcode = opcode
        return self
    
    def with_flags(self, authoritative: bool = None, truncated: bool = None,
                   recursion_desired: bool = None, recursion_available: bool = None,
                   is_response: bool = None) -> 'DNSQueryBuilder':
        """Set various flags."""
        if authoritative is not None:
            self._query.authoritative = authoritative
        if truncated is not None:
            self._query.truncated = truncated
        if recursion_desired is not None:
            self._query.recursion_desired = recursion_desired
        if recursion_available is not None:
            self._query.recursion_available = recursion_available
        if is_response is not None:
            self._query.is_response = is_response
        return self
    
    def with_question(self, qname: str, qtype: str = "A", qclass: str = "IN") -> 'DNSQueryBuilder':
        """Set the question section."""
        self._query.qname = qname
        self._query.qtype = qtype
        self._query.qclass = qclass
        return self
    
    def query_name(self, qname: str) -> 'DNSQueryBuilder':
        """Set the query name (alias for with_question name part)."""
        self._query.qname = qname
        return self
    
    def query_type(self, qtype: str) -> 'DNSQueryBuilder':
        """Set the query type."""
        self._query.qtype = qtype
        return self
    
    def query_class(self, qclass: str) -> 'DNSQueryBuilder':
        """Set the query class."""
        self._query.qclass = qclass
        return self
    
    def query_id(self, query_id: int) -> 'DNSQueryBuilder':
        """Set the query ID (alias for with_id)."""
        self._query.query_id = query_id
        return self
    
    def recursion_desired(self, rd: bool) -> 'DNSQueryBuilder':
        """Set recursion desired flag."""
        self._query.recursion_desired = rd
        return self
    
    def authoritative(self, aa: bool) -> 'DNSQueryBuilder':
        """Set authoritative flag."""
        self._query.authoritative = aa
        return self
    
    def truncated(self, tc: bool) -> 'DNSQueryBuilder':
        """Set truncated flag."""
        self._query.truncated = tc
        return self
    
    def as_response(self) -> 'DNSQueryBuilder':
        """Mark this as a response."""
        self._query.is_response = True
        return self
    
    def response_code(self, rcode: Union[DNSRcode, int]) -> 'DNSQueryBuilder':
        """Set the response code."""
        if isinstance(rcode, int):
            rcode = DNSRcode(rcode)
        self._query.response_code = rcode
        return self
    
    def add_answer(self, answer: Dict[str, Any]) -> 'DNSQueryBuilder':
        """Add an answer record."""
        self._query.answers.append(answer)
        return self
    
    def edns_version(self, version: int) -> 'DNSQueryBuilder':
        """Set EDNS version."""
        self._query.edns_version = version
        return self
    
    def edns_payload_size(self, size: int) -> 'DNSQueryBuilder':
        """Set EDNS payload size."""
        self._query.edns_payload_size = size
        return self
    
    def edns_dnssec_ok(self, dnssec_ok: bool) -> 'DNSQueryBuilder':
        """Set EDNS DNSSEC OK flag."""
        self._query.edns_dnssec_ok = dnssec_ok
        return self
    
    def with_answer(self, name: str, rtype: str, rdata: str, ttl: int = 300,
                    rclass: str = "IN") -> 'DNSQueryBuilder':
        """Add an answer record."""
        self._query.answers.append({
            'name': name,
            'type': rtype,
            'class': rclass,
            'ttl': ttl,
            'rdata': rdata
        })
        return self
    
    def with_authority(self, name: str, rtype: str, rdata: str, ttl: int = 300,
                      rclass: str = "IN") -> 'DNSQueryBuilder':
        """Add an authority record."""
        self._query.authorities.append({
            'name': name,
            'type': rtype,
            'class': rclass,
            'ttl': ttl,
            'rdata': rdata
        })
        return self
    
    def with_additional(self, name: str, rtype: str, rdata: str, ttl: int = 300,
                       rclass: str = "IN") -> 'DNSQueryBuilder':
        """Add an additional record."""
        self._query.additional.append({
            'name': name,
            'type': rtype,
            'class': rclass,
            'ttl': ttl,
            'rdata': rdata
        })
        return self
    
    def with_edns(self, version: int = 0, payload_size: int = 1232,
                  dnssec_ok: bool = False) -> 'DNSQueryBuilder':
        """Configure EDNS options."""
        self._query.edns_version = version
        self._query.edns_payload_size = payload_size
        self._query.edns_dnssec_ok = dnssec_ok
        return self
    
    def with_rcode(self, rcode: Union[DNSRcode, int]) -> 'DNSQueryBuilder':
        """Set the response code."""
        if isinstance(rcode, int):
            rcode = DNSRcode(rcode)
        self._query.response_code = rcode
        return self
    
    def build(self) -> DNSQuery:
        """Build and return the DNSQuery."""
        return self._query
    
    def reset(self) -> 'DNSQueryBuilder':
        """Reset the builder to create a new query."""
        self._query = DNSQuery()
        return self


def create_basic_query(qname: str = "example.com", qtype: str = "A") -> DNSQuery:
    """Create a basic DNS query."""
    return DNSQueryBuilder().with_question(qname, qtype).build()


def create_response_query(qname: str = "example.com", qtype: str = "A",
                         answer_rdata: str = "127.0.0.1") -> DNSQuery:
    """Create a basic DNS response."""
    return (DNSQueryBuilder()
            .with_question(qname, qtype)
            .with_flags(is_response=True, authoritative=True)
            .with_answer(qname, qtype, answer_rdata)
            .build())