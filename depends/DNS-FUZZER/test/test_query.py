"""Tests for DNS query module."""

import pytest
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.flags
import dns.rrset
import dns.name
import dns.rdata
from dnsfuzzer.core.query import DNSQuery, DNSQueryBuilder, DNSOpcode, DNSRcode


class TestDNSQuery:
    """Test cases for DNSQuery class."""
    
    def test_create_basic_query(self):
        """Test creating a basic DNS query."""
        query = DNSQuery(
            qname="example.com",
            qtype="A",
            qclass="IN",
            query_id=12345
        )
        
        assert query.qname == "example.com"
        assert query.qtype == "A"
        assert query.qclass == "IN"
        assert query.query_id == 12345
        assert not query.is_response
        assert query.opcode == DNSOpcode.QUERY
        assert query.response_code == DNSRcode.NOERROR
    
    def test_clone_query(self):
        """Test cloning a DNS query."""
        original = DNSQuery(
            qname="test.com",
            qtype="AAAA",
            qclass="IN",
            query_id=54321,
            recursion_desired=True
        )
        
        cloned = original.clone()
        
        assert cloned.qname == original.qname
        assert cloned.qtype == original.qtype
        assert cloned.qclass == original.qclass
        assert cloned.query_id == original.query_id
        assert cloned.recursion_desired == original.recursion_desired
        
        # Ensure it's a different object
        assert cloned is not original
        
        # Ensure lists are separate objects
        assert cloned.answers is not original.answers
        assert cloned.authorities is not original.authorities
        assert cloned.additional is not original.additional
        assert cloned.edns_options is not original.edns_options

    def test_to_dns_message(self):
        """Test converting DNSQuery to dns.message.Message."""
        query = DNSQuery(
            qname="convert.test.com",
            qtype="A",
            qclass="IN",
            query_id=9999,
            authoritative=True,
            recursion_desired=False
        )
        
        msg = query.to_dns_message()
        
        assert msg.id == 9999
        assert bool(msg.flags & dns.flags.AA)  # Authoritative
        assert not bool(msg.flags & dns.flags.RD)  # No recursion desired
        assert len(msg.question) == 1
        assert str(msg.question[0].name) == "convert.test.com."
        assert msg.question[0].rdtype == dns.rdatatype.A

    def test_from_dns_message(self):
        """Test creating DNSQuery from dns.message.Message."""
        # Create a DNS message
        msg = dns.message.make_query("test.example.com", "A")
        msg.id = 7777
        msg.flags |= dns.flags.RD  # Set recursion desired
        
        query = DNSQuery.from_dns_message(msg)
        
        assert query.qname == "test.example.com"
        assert query.qtype == "A"
        assert query.qclass == "IN"
        assert query.query_id == 7777
        assert query.recursion_desired
        assert not query.is_response
    
    def test_to_wire_format(self):
        """Test converting DNSQuery to wire format."""
        query = DNSQuery(
            qname="wire.test.com",
            qtype="A",
            qclass="IN",
            query_id=1111
        )
        
        wire_data = query.to_wire()
        
        assert isinstance(wire_data, bytes)
        assert len(wire_data) > 0
        
        # Parse back and verify
        parsed_msg = dns.message.from_wire(wire_data)
        assert parsed_msg.id == 1111
        assert str(parsed_msg.question[0].name) == "wire.test.com."

    def test_from_wire_format(self):
        """Test creating DNSQuery from wire format."""
        # Create a message and convert to wire
        original_msg = dns.message.make_query("wire.example.com", "AAAA")
        original_msg.id = 2222
        wire_data = original_msg.to_wire()
        
        # Create DNSQuery from wire
        query = DNSQuery.from_wire(wire_data)
        
        assert query.qname == "wire.example.com"
        assert query.qtype == "AAAA"
        assert query.query_id == 2222

    def test_response_query(self):
        """Test creating and handling response queries."""
        query = DNSQuery(
            qname="response.test.com",
            qtype="A",
            qclass="IN",
            query_id=3333,
            is_response=True,
            authoritative=True,
            response_code=DNSRcode.NOERROR
        )
        
        msg = query.to_dns_message()
        
        assert bool(msg.flags & dns.flags.QR)  # Response flag
        assert bool(msg.flags & dns.flags.AA)  # Authoritative
        assert msg.rcode() == DNSRcode.NOERROR

    def test_with_answers(self):
        """Test DNSQuery with answer records."""
        query = DNSQuery(
            qname="answer.test.com",
            qtype="A",
            answers=[{
                'name': 'answer.test.com',
                'type': 'A',
                'class': 'IN',
                'ttl': 300,
                'rdata': '192.168.1.1'
            }]
        )
        
        msg = query.to_dns_message()
        assert len(msg.answer) == 1
        assert str(msg.answer[0].name) == "answer.test.com."
        assert msg.answer[0].rdtype == dns.rdatatype.A

    def test_add_record_to_section_normal(self):
        """Test _add_record_to_section method with normal records."""
        query = DNSQuery()
        section = []
        
        # Test A record
        record_data = {
            'name': 'test.example.com',
            'type': 'A',
            'class': 'IN',
            'ttl': 300,
            'rdata': '192.168.1.1'
        }
        
        query._add_record_to_section(section, record_data)
        
        assert len(section) == 1
        assert str(section[0].name) == "test.example.com."
        assert section[0].rdtype == dns.rdatatype.A
        assert section[0].ttl == 300

    def test_add_record_to_section_different_types(self):
        """Test _add_record_to_section with different record types."""
        query = DNSQuery()
        section = []
        
        # Test MX record
        mx_record = {
            'name': 'example.com',
            'type': 'MX',
            'class': 'IN',
            'ttl': 3600,
            'rdata': '10 mail.example.com.'
        }
        
        query._add_record_to_section(section, mx_record)
        assert len(section) == 1
        assert section[0].rdtype == dns.rdatatype.MX
        
        # Test CNAME record
        cname_record = {
            'name': 'www.example.com',
            'type': 'CNAME',
            'class': 'IN',
            'ttl': 300,
            'rdata': 'example.com.'
        }
        
        query._add_record_to_section(section, cname_record)
        assert len(section) == 2
        assert section[1].rdtype == dns.rdatatype.CNAME

    def test_add_record_to_section_invalid_data(self):
        """Test _add_record_to_section with invalid data."""
        query = DNSQuery()
        section = []
        
        # Test with invalid rdata
        invalid_record = {
            'name': 'invalid.example.com',
            'type': 'A',
            'class': 'IN',
            'ttl': 300,
            'rdata': 'invalid-ip-address'
        }
        
        # Should not raise exception, but should skip the record
        query._add_record_to_section(section, invalid_record)
        # The record should be skipped due to invalid rdata
        assert len(section) == 0

    def test_extract_section_method(self):
        """Test _extract_section static method."""
        # Create a mock section with RRsets
        msg = dns.message.make_query("test.example.com", "A")
        
        # Add an answer record
        name = dns.name.from_text("test.example.com")
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1")
        rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.A)
        rrset.add(rdata, 300)
        
        section = [rrset]
        
        # Test extraction
        records = DNSQuery._extract_section(section)
        
        assert len(records) == 1
        assert records[0]['name'] == 'test.example.com'
        assert records[0]['type'] == 'A'
        assert records[0]['class'] == 'IN'
        assert records[0]['ttl'] == 300
        assert records[0]['rdata'] == '192.168.1.1'

    def test_edns_functionality(self):
        """Test EDNS related functionality."""
        query = DNSQuery(
            qname="edns.test.com",
            qtype="A",
            edns_version=0,
            edns_payload_size=4096,
            edns_dnssec_ok=True
        )
        
        msg = query.to_dns_message()
        
        assert msg.edns >= 0  # EDNS is enabled
        assert msg.payload == 4096
        assert bool(msg.flags & dns.flags.DO)  # DNSSEC OK flag

    def test_edns_from_message(self):
        """Test extracting EDNS information from DNS message."""
        # Create a message with EDNS
        msg = dns.message.make_query("edns.example.com", "A")
        msg.use_edns(edns=0, payload=2048)
        msg.flags |= dns.flags.DO  # Set DNSSEC OK
        
        query = DNSQuery.from_dns_message(msg)
        
        assert query.edns_version == 0
        assert query.edns_payload_size == 2048
        assert query.edns_dnssec_ok

    def test_different_opcodes(self):
        """Test different DNS opcodes."""
        query = DNSQuery(
            qname="opcode.test.com",
            opcode=DNSOpcode.IQUERY
        )
        
        msg = query.to_dns_message()
        assert msg.opcode() == DNSOpcode.IQUERY

    def test_different_rcodes(self):
        """Test different response codes."""
        query = DNSQuery(
            qname="rcode.test.com",
            is_response=True,
            response_code=DNSRcode.NXDOMAIN
        )
        
        msg = query.to_dns_message()
        assert msg.rcode() == DNSRcode.NXDOMAIN

    def test_all_flags_combination(self):
        """Test various flag combinations."""
        query = DNSQuery(
            qname="flags.test.com",
            is_response=True,
            authoritative=True,
            truncated=True,
            recursion_desired=True,
            recursion_available=True
        )
        
        msg = query.to_dns_message()
        
        assert bool(msg.flags & dns.flags.QR)  # Response
        assert bool(msg.flags & dns.flags.AA)  # Authoritative
        assert bool(msg.flags & dns.flags.TC)  # Truncated
        assert bool(msg.flags & dns.flags.RD)  # Recursion Desired
        assert bool(msg.flags & dns.flags.RA)  # Recursion Available


class TestDNSQueryBuilder:
    """Test cases for DNSQueryBuilder class."""
    
    def test_basic_builder(self):
        """Test basic query building."""
        query = (DNSQueryBuilder()
                .query_name("builder.test.com")
                .query_type("A")
                .query_class("IN")
                .query_id(5555)
                .build())
        
        assert query.qname == "builder.test.com"
        assert query.qtype == "A"
        assert query.qclass == "IN"
        assert query.query_id == 5555
    
    def test_builder_with_flags(self):
        """Test builder with various flags."""
        query = (DNSQueryBuilder()
                .query_name("flags.test.com")
                .query_type("MX")
                .recursion_desired(True)
                .authoritative(True)
                .truncated(False)
                .build())
        
        assert query.qname == "flags.test.com"
        assert query.qtype == "MX"
        assert query.recursion_desired
        assert query.authoritative
        assert not query.truncated
    
    def test_builder_response(self):
        """Test building a response."""
        query = (DNSQueryBuilder()
                .query_name("response.test.com")
                .query_type("A")
                .as_response()
                .response_code(DNSRcode.NXDOMAIN)
                .build())
        
        assert query.qname == "response.test.com"
        assert query.is_response
        assert query.response_code == DNSRcode.NXDOMAIN
    
    def test_builder_with_records(self):
        """Test builder with answer records."""
        answer = {
            'name': 'records.test.com',
            'type': 'A',
            'class': 'IN',
            'ttl': 600,
            'rdata': '203.0.113.1'
        }
        
        query = (DNSQueryBuilder()
                .query_name("records.test.com")
                .query_type("A")
                .as_response()
                .add_answer(answer)
                .build())
        
        assert len(query.answers) == 1
        assert query.answers[0]['name'] == 'records.test.com'
        assert query.answers[0]['rdata'] == '203.0.113.1'
    
    def test_builder_edns(self):
        """Test builder with EDNS options."""
        query = (DNSQueryBuilder()
                .query_name("edns.test.com")
                .query_type("A")
                .edns_version(0)
                .edns_payload_size(4096)
                .edns_dnssec_ok(True)
                .build())
        
        assert query.qname == "edns.test.com"
        assert query.edns_version == 0
        assert query.edns_payload_size == 4096
        assert query.edns_dnssec_ok
    
    def test_builder_reset(self):
        """Test builder reset functionality."""
        builder = DNSQueryBuilder()
        
        # Build first query
        query1 = (builder
                 .query_name("first.test.com")
                 .query_type("A")
                 .build())
        
        # Reset and build second query
        query2 = (builder
                 .reset()
                 .query_name("second.test.com")
                 .query_type("AAAA")
                 .build())
        
        assert query1.qname == "first.test.com"
        assert query1.qtype == "A"
        assert query2.qname == "second.test.com"
        assert query2.qtype == "AAAA"


class TestHelperFunctions:
    """Test cases for helper functions."""
    
    def test_create_basic_query(self):
        """Test create_basic_query helper function."""
        from dnsfuzzer.core.query import create_basic_query
        
        query = create_basic_query("helper.test.com", "A")
        
        assert query.qname == "helper.test.com"
        assert query.qtype == "A"
        assert query.qclass == "IN"
        assert not query.is_response
        assert query.recursion_desired  # Should be True by default
    
    def test_create_basic_response(self):
        """Test create_basic_response helper function."""
        from dnsfuzzer.core.query import create_response_query
        
        response = create_response_query("response.test.com", "A", "127.0.0.1")
        
        assert response.qname == "response.test.com"
        assert response.qtype == "A"
        assert response.qclass == "IN"
        assert response.is_response
        assert response.response_code == DNSRcode.NOERROR


if __name__ == "__main__":
    pytest.main([__file__])