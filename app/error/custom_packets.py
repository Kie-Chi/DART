"""Custom DNS packet generators for RFC compliance testing.

This module provides various packet generators for testing RFC compliance
scenarios that cannot be easily created with the standard query format.

Note: This module uses variables injected by the CustomPacketGenerator:
- DNSQuery, create_basic_query: from dnsfuzzer.core.query
- dns: dnspython package
"""

# The following variables are injected by CustomPacketGenerator:
# - DNSQuery, create_basic_query (from dnsfuzzer.core.query)
# - dns (dnspython package)


# =============================================================================
# RFC1123 Tests
# =============================================================================

def gen_tc_truncated() -> bytes:
    """
    Generate a truncated DNS packet (TC flag set with physical truncation).

    RFC1123 Section 6.1.3.2: Resolver must not cache resource records from
    packets with TC flag set.

    Returns:
        Truncated DNS packet bytes
    """
    query = create_basic_query("example.com", "A")
    query.truncated = True
    wire = query.to_wire()
    # Physically truncate to 20 bytes (cut off in the middle)
    return wire[:20]


def gen_ttl_zero_response() -> bytes:
    """
    Generate a DNS response with TTL=0.

    RFC1123 Section 6.1.2.1: Resolver should handle TTL=0 records correctly
    and not cache them.

    Returns:
        DNS response packet bytes with TTL=0
    """
    query = DNSQuery()
    query.is_response = True
    query.qname = "example.com"
    query.qtype = "A"
    query.qclass = "IN"
    query.recursion_available = True
    query.recursion_desired = True

    query.answers = [{
        'name': 'example.com',
        'type': 'A',
        'class': 'IN',
        'ttl': 0,
        'rdata': '93.184.216.34'
    }]

    return query.to_wire()


# =============================================================================
# RFC2308 Tests
# =============================================================================

def gen_soa_ttl_minimum() -> bytes:
    """
    Generate a DNS response with SOA record where TTL should be minimum of
    TTL and MINIMUM field.

    RFC2308 Section 3: SOA TTL should be the minimum of TTL and MINIMUM field.

    Returns:
        DNS response packet bytes with SOA record
    """
    # Create a negative response with SOA record using absolute names
    msg = dns.message.make_response(dns.message.make_query('nonexist.example.com.', 'A'))
    msg.set_rcode(dns.rcode.NXDOMAIN)

    # Add SOA record with TTL larger than MINIMUM - use absolute names
    soa = dns.rrset.from_text(
        'example.com.', 300, 'IN', 'SOA',
        'ns1.example.com. admin.example.com. 1 3600 1800 604800 60'  # MINIMUM=60, TTL=300
    )
    msg.authority.append(soa)

    return msg.to_wire()


def gen_negative_response_soa() -> bytes:
    """
    Generate a negative response with SOA record for caching test.

    RFC2308 Section 8: Resolver should cache SOA record from negative response.

    Returns:
        DNS response packet bytes with NXDOMAIN and SOA
    """
    msg = dns.message.make_response(dns.message.make_query('nonexist.example.com.', 'A'))
    msg.set_rcode(dns.rcode.NXDOMAIN)

    soa = dns.rrset.from_text(
        'example.com.', 300, 'IN', 'SOA',
        'ns1.example.com. admin.example.com. 2024010101 3600 1800 604800 86400'
    )
    msg.authority.append(soa)

    return msg.to_wire()


# =============================================================================
# RFC2930 Tests
# =============================================================================

def gen_tkey_query() -> bytes:
    """
    Generate a TKEY query to test not-implemented/refused response.

    RFC2930 Section 3: TKEY is point-to-point, unimplemented should return
    NOTIMP or REFUSED.

    Returns:
        DNS query packet bytes for TKEY
    """
    query = create_basic_query("example.com", "TKEY")
    return query.to_wire()


# =============================================================================
# RFC3403 Tests
# =============================================================================

def gen_naptr_both_fields() -> bytes:
    """
    Generate a NAPTR response with both REGEXP and REPLACEMENT fields.

    RFC3403 Section 4.1: REGEXP and REPLACEMENT are mutually exclusive.
    Record with both should be ignored or return error.

    Returns:
        DNS response packet bytes with malformed NAPTR
    """
    # Create raw packet with malformed NAPTR
    header = bytes([
        0x12, 0x34,  # Transaction ID
        0x81, 0x80,  # Flags: response, RA
        0x00, 0x01,  # Questions: 1
        0x00, 0x01,  # Answer RRs: 1
        0x00, 0x00,  # Authority RRs: 0
        0x00, 0x00,  # Additional RRs: 0
    ])

    # Question section
    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,  # "example"
        0x03, 0x63, 0x6f, 0x6d,  # "com"
        0x00,  # End of name
        0x00, 0x23,  # Type NAPTR (35)
        0x00, 0x01,  # Class IN
    ])

    # Answer section: malformed NAPTR with both REGEXP and REPLACEMENT
    naptr_answer = bytes([
        0xc0, 0x0c,  # Name: pointer to question name
        0x00, 0x23,  # Type NAPTR (35)
        0x00, 0x01,  # Class IN
        0x00, 0x00, 0x01, 0x2c,  # TTL: 300
        0x00, 0x1f,  # RDATA length (31 bytes)
        0x00, 0x01,  # Order: 1
        0x00, 0x01,  # Preference: 1
        0x01, 0x53, 0x00,  # Flags: "S" (length-prefixed)
        0x04, 0x68, 0x74, 0x74, 0x70, 0x00,  # Services: "http" (length-prefixed)
        0x05, 0x5c, 0x2a, 0x5c, 0x2a, 0x00,  # REGEXP: "\\*\\*" (non-empty)
        0xc0, 0x0c,  # REPLACEMENT: pointer (non-null means present)
    ])

    return header + question + naptr_answer


# =============================================================================
# RFC6672 Tests
# =============================================================================

def gen_dname_query() -> bytes:
    """
    Generate a DNAME query.

    RFC6672 Section 3.4: Recursive resolver should resolve DNAME records.

    Returns:
        DNS query packet bytes for DNAME
    """
    query = create_basic_query("example.com", "DNAME")
    return query.to_wire()


def gen_dname_response() -> bytes:
    """
    Generate a DNAME response.

    RFC6672 Section 3.4: DNAME response should be treated as answer.

    Returns:
        DNS response packet bytes with DNAME record
    """
    msg = dns.message.make_response(dns.message.make_query('sub.example.com.', 'A'))

    # Add DNAME record with absolute names
    dname = dns.rrset.from_text(
        'example.com.', 300, 'IN', 'DNAME',
        'target.com.'
    )
    msg.answer.append(dname)

    return msg.to_wire()


# =============================================================================
# RFC6761 Tests
# =============================================================================

def gen_localhost_aaaa() -> bytes:
    """
    Generate a query for localhost. AAAA record.

    RFC6761 Section 6.3: Query for localhost. AAAA should return ::1.

    Returns:
        DNS query packet bytes
    """
    query = create_basic_query("localhost", "AAAA")
    return query.to_wire()


def gen_test_domain_ns() -> bytes:
    """
    Generate a query for test. NS record.

    RFC6761 Section 6.2: test. domain should be recognized as special.

    Returns:
        DNS query packet bytes
    """
    query = create_basic_query("test", "NS")
    return query.to_wire()


def gen_invalid_domain_ns() -> bytes:
    """
    Generate a query for invalid. NS record.

    RFC6761 Section 6.4: invalid. domain should be recognized as special.

    Returns:
        DNS query packet bytes
    """
    query = create_basic_query("invalid", "NS")
    return query.to_wire()


def gen_localhost_a() -> bytes:
    """
    Generate a query for localhost. A record.

    RFC6761 Section 6.3: localhost. should return 127.0.0.1 for A.

    Returns:
        DNS query packet bytes
    """
    query = create_basic_query("localhost", "A")
    return query.to_wire()


# =============================================================================
# RFC6891 Tests (EDNS)
# =============================================================================

def gen_multi_opt_records() -> bytes:
    """
    Generate a DNS packet with multiple OPT records.

    RFC6891 Section 6.1.1: A message should have only one OPT record.
    Multiple OPT records should return FORMERR.

    Returns:
        DNS packet bytes with multiple OPT records
    """
    msg = dns.message.make_query('example.com.', 'A')
    msg.use_edns(edns=0, payload=1232)

    wire = msg.to_wire()

    # Append a second OPT record
    second_opt = bytes([
        0x00,           # NAME: root (0)
        0x00, 0x29,     # TYPE: OPT (41)
        0x10, 0x00,     # CLASS: UDP payload 4096
        0x00,           # Extended RCODE
        0x00,           # EDNS version
        0x00, 0x00,     # Flags
        0x00, 0x00,     # RDLEN: 0
    ])

    # Update ARCOUNT
    header = bytearray(wire[:12])
    arcount = (header[10] << 8) | header[11]
    arcount += 1
    header[10] = (arcount >> 8) & 0xff
    header[11] = arcount & 0xff

    return bytes(header) + wire[12:] + second_opt


def gen_opt_non_root_name() -> bytes:
    """
    Generate a DNS packet with OPT record having non-root NAME field.

    RFC6891 Section 6.1.2: OPT record NAME field must be 0 (root domain).

    Returns:
        DNS packet bytes with malformed OPT record
    """
    header = bytes([
        0x12, 0x34,  # Transaction ID
        0x01, 0x00,  # Flags: standard query
        0x00, 0x01,  # Questions: 1
        0x00, 0x00,  # Answer RRs: 0
        0x00, 0x00,  # Authority RRs: 0
        0x00, 0x01,  # Additional RRs: 1
    ])

    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x01,  # Type A
        0x00, 0x01,  # Class IN
    ])

    # OPT with non-root name
    additional = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x00,
        0x00, 0x29,  # Type OPT (41)
        0x04, 0xd0,  # UDP payload size: 1232
        0x00,
        0x00,
        0x00, 0x00,
        0x00, 0x00,
    ])

    return header + question + additional


def gen_badvers_response() -> bytes:
    """
    Generate a DNS response with BADVERS RCODE.

    RFC6891 Section 6.1.3: If responder doesn't implement requested VERSION,
    respond with BADVERS.

    Returns:
        DNS response packet bytes with BADVERS
    """
    msg = dns.message.make_response(dns.message.make_query('example.com.', 'A'))
    msg.use_edns(edns=0, payload=1232)
    msg.set_rcode(dns.rcode.BADVERS)

    return msg.to_wire()


def gen_opt_invalid_value() -> bytes:
    """
    Generate a DNS packet with OPT having invalid/out-of-range values.

    RFC6891 Section 7: Invalid OPT values should return FORMERR.

    Returns:
        DNS packet bytes with malformed OPT
    """
    header = bytes([
        0x12, 0x34,  # Transaction ID
        0x01, 0x00,  # Flags: standard query
        0x00, 0x01,  # Questions: 1
        0x00, 0x00,  # Answer RRs: 0
        0x00, 0x00,  # Authority RRs: 0
        0x00, 0x01,  # Additional RRs: 1
    ])

    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    ])

    # OPT with invalid extended RCODE (max valid is 15, we use 255)
    additional = bytes([
        0x00,           # NAME: root
        0x00, 0x29,     # Type OPT (41)
        0x04, 0xd0,     # UDP payload size: 1232
        0xff,           # Extended RCODE: 255 (invalid)
        0xff,           # EDNS version: 255 (invalid)
        0xff, 0xff,     # Flags: invalid
        0x00, 0x00,     # RDLEN: 0
    ])

    return header + question + additional


def gen_edns_version_high() -> bytes:
    """
    Generate a DNS query with high EDNS version.

    RFC6891 Section 6.1.3: Requesting unsupported version should get BADVERS.

    Returns:
        DNS query packet bytes with EDNS version > 0
    """
    header = bytes([
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x01,
    ])

    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    ])

    # OPT with EDNS version 10 (unsupported)
    additional = bytes([
        0x00,
        0x00, 0x29,
        0x04, 0xd0,
        0x00,
        0x0a,  # EDNS version: 10 (unsupported)
        0x00, 0x00,
        0x00, 0x00,
    ])

    return header + question + additional


# =============================================================================
# RFC7830 Tests (Padding)
# =============================================================================

def gen_multi_padding_options() -> bytes:
    """
    Generate a DNS packet with multiple PADDING options in OPT.

    RFC7830 Section 3: PADDING option should appear only once per OPT.
    Multiple appearances should be treated as anomaly.

    Returns:
        DNS packet bytes with multiple PADDING options
    """
    # Manually construct packet with two PADDING options
    header = bytes([
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x01,
    ])

    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    ])

    # OPT with two PADDING options (code 12)
    opt_rdata = bytes([
        0x00, 0x0c,  # Option code: PADDING (12)
        0x00, 0x05,  # Length: 5
        0x00, 0x00, 0x00, 0x00, 0x00,  # Padding data
        0x00, 0x0c,  # Second PADDING option (invalid)
        0x00, 0x03,  # Length: 3
        0x00, 0x00, 0x00,  # Padding data
    ])

    additional = bytes([
        0x00,
        0x00, 0x29,
        0x04, 0xd0,
        0x00,
        0x00,
        0x00, 0x00,
        0x00, 0x10,  # RDLEN: 16 (size of opt_rdata)
    ]) + opt_rdata

    return header + question + additional


# =============================================================================
# RFC7686 Tests (.onion)
# =============================================================================

def gen_onion_domain() -> bytes:
    """
    Generate a query for a .onion domain.

    RFC7686 Section 2: .onion domains should return NXDOMAIN and not be
    forwarded.

    Returns:
        DNS query packet bytes
    """
    query = create_basic_query("example.onion", "A")
    return query.to_wire()


# =============================================================================
# RFC7793 Tests (Shared Address Space)
# =============================================================================

def gen_shared_address_ptr() -> bytes:
    """
    Generate a reverse DNS query for 100.64.0.0/10 address space.

    RFC7793 Section 1: Reverse DNS queries for 100.64.0.0/10 should not be
    forwarded outward.

    Returns:
        DNS query packet bytes for PTR
    """
    # 100.64.0.1 -> 1.0.64.100.in-addr.arpa
    query = create_basic_query("1.0.64.100.in-addr.arpa", "PTR")
    return query.to_wire()


# =============================================================================
# RFC8020 Tests (NXDOMAIN)
# =============================================================================

def gen_nxdomain_response() -> bytes:
    """
    Generate a NXDOMAIN response for subtree caching test.

    RFC8020 Section 2: NXDOMAIN response should be cached and entire subtree
    treated as non-existent.

    Returns:
        DNS response packet bytes with NXDOMAIN
    """
    msg = dns.message.make_response(dns.message.make_query('nonexist.example.com.', 'A'))
    msg.set_rcode(dns.rcode.NXDOMAIN)

    soa = dns.rrset.from_text(
        'example.com.', 300, 'IN', 'SOA',
        'ns1.example.com. admin.example.com. 1 3600 1800 604800 86400'
    )
    msg.authority.append(soa)

    return msg.to_wire()


# =============================================================================
# RFC8375 Tests (home.arpa)
# =============================================================================

def gen_home_arpa() -> bytes:
    """
    Generate a query for home.arpa. domain.

    RFC8375 Section 3: home.arpa. should be recognized as special.

    Returns:
        DNS query packet bytes
    """
    query = create_basic_query("home.arpa", "A")
    return query.to_wire()


# =============================================================================
# RFC8659 Tests (CAA)
# =============================================================================

def gen_caa_invalid_issue() -> bytes:
    """
    Generate a CAA record with invalid issue property value.

    RFC8659 Section 4.2: CAA issue property must conform to ABNF syntax.
    Invalid value should be treated as empty issuer domain.

    Returns:
        DNS response packet bytes with malformed CAA
    """
    msg = dns.message.make_response(dns.message.make_query('example.com.', 'CAA'))

    # Create CAA with invalid issue value
    caa = dns.rrset.from_text(
        'example.com.', 300, 'IN', 'CAA',
        '0 issue "not-a-valid;domain;format!!"'
    )
    msg.answer.append(caa)

    return msg.to_wire()


# =============================================================================
# RFC8945 Tests (TSIG)
# =============================================================================

def gen_multi_tsig_records() -> bytes:
    """
    Generate a DNS packet with multiple TSIG records.

    RFC8945 Section 5.2: Request with multiple TSIG records should return
    FORMERR.

    Returns:
        DNS packet bytes with multiple TSIG records
    """
    header = bytes([
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x02,  # Additional RRs: 2
    ])

    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    ])

    # Two TSIG records (minimal structure)
    tsig1 = bytes([
        0x07, 0x74, 0x73, 0x69, 0x67, 0x2d, 0x6b, 0x65, 0x79,  # "tsig-key"
        0x00,
        0x00, 0xfa,  # Type TSIG (250)
        0x00, 0xff,  # Class ANY (255)
        0x00, 0x00, 0x00, 0x00,  # TTL: 0
        0x00, 0x10,  # RDLEN: 16
        0x00, 0x00, 0x00, 0x00,  # Time Signed
        0x00, 0x01,  # Fudge: 1
        0x00, 0x00,  # MAC Size: 0
        0x00, 0x00,  # Original ID
        0x00, 0x00,  # Error
        0x00, 0x00,  # Other Len: 0
    ])

    tsig2 = bytes([
        0x07, 0x74, 0x73, 0x69, 0x67, 0x2d, 0x6b, 0x32,  # "tsig-k2"
        0x00,
        0x00, 0xfa,
        0x00, 0xff,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
    ])

    return header + question + tsig1 + tsig2


# =============================================================================
# RFC8914 Tests (Extended DNS Errors)
# =============================================================================

def gen_rd_flag_clear() -> bytes:
    """
    Generate a DNS query with RD flag clear.

    RFC8914 Section 4.21: When resolver receives request without RD flag,
    should return REFUSED with Extended DNS Error Code 20.

    Returns:
        DNS query packet bytes with RD=0
    """
    query = create_basic_query("example.com", "A")
    query.recursion_desired = False
    return query.to_wire()


# =============================================================================
# RFC9460 Tests (SVCB/HTTPS)
# =============================================================================

def gen_svcb_alias_and_service() -> bytes:
    """
    Generate a response with both AliasMode and ServiceMode SVCB records.

    RFC9460 Section 2.4.1: If response contains both AliasMode and ServiceMode
    SVCB, keep only AliasMode.

    Returns:
        DNS response packet bytes with mixed SVCB modes
    """
    msg = dns.message.make_response(dns.message.make_query('example.com.', 'SVCB'))

    # AliasMode SVCB (priority=0)
    alias_svcb = dns.rrset.from_text(
        'example.com.', 300, 'IN', 'SVCB',
        '0 target.example.com.'
    )
    msg.answer.append(alias_svcb)

    # ServiceMode SVCB (priority>0)
    service_svcb = dns.rrset.from_text(
        'example.com.', 300, 'IN', 'SVCB',
        '100 target.example.com. alpn=h2'
    )
    msg.answer.append(service_svcb)

    return msg.to_wire()


def gen_svcb_alias_with_params() -> bytes:
    """
    Generate AliasMode SVCB with SvcParams (should be ignored).
    Note: dnspython doesn't allow this, so we construct raw bytes.

    RFC9460 Section 2.4.2: AliasMode SVCB SvcParams must be ignored.

    Returns:
        DNS response packet bytes (raw construction)
    """
    # Construct raw packet with AliasMode SVCB having params
    header = bytes([
        0x12, 0x34,
        0x81, 0x80,  # Flags: response, RA
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
    ])

    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x40,  # Type SVCB (64)
        0x00, 0x01,
    ])

    # SVCB Answer with AliasMode (priority=0) but with params
    # SVCB format: priority(2) target-name svcparams
    svcb_answer = bytes([
        0xc0, 0x0c,  # Name pointer
        0x00, 0x40,  # Type SVCB
        0x00, 0x01,  # Class IN
        0x00, 0x00, 0x01, 0x2c,  # TTL: 300
        0x00, 0x18,  # RDLEN: 24
        0x00, 0x00,  # Priority: 0 (AliasMode)
        0x07, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,  # "target"
        0x03, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,  # "example"
        0x03, 0x63, 0x6f, 0x6d,  # "com"
        0x00,  # End target name
        # SvcParams (invalid for AliasMode but included for testing)
        0x00, 0x01,  # alpn key (1)
        0x00, 0x02,  # length 2
        0x02, 0x68, 0x32,  # "h2"
    ])

    return header + question + svcb_answer


def gen_svcb_alias_to_root() -> bytes:
    """
    Generate AliasMode SVCB pointing to root (should be ignored).

    RFC9460 Section 12: AliasMode pointing to root should be ignored.

    Returns:
        DNS response packet bytes (raw construction)
    """
    # Construct raw packet
    header = bytes([
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
    ])

    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x40,
        0x00, 0x01,
    ])

    # SVCB pointing to root (invalid)
    svcb_answer = bytes([
        0xc0, 0x0c,
        0x00, 0x40,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x04,  # RDLEN: 4
        0x00, 0x00,  # Priority: 0 (AliasMode)
        0x00,  # Target: root (empty)
    ])

    return header + question + svcb_answer


def gen_svcb_missing_alpn() -> bytes:
    """
    Generate ServiceMode SVCB without alpn SvcParamKey.

    RFC9461 Section 4.1: SVCB without alpn is anomalous.

    Returns:
        DNS response packet bytes (raw construction)
    """
    header = bytes([
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
    ])

    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x40,
        0x00, 0x01,
    ])

    # SVCB without alpn
    svcb_answer = bytes([
        0xc0, 0x0c,
        0x00, 0x40,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x12,  # RDLEN
        0x00, 0x64,  # Priority: 100 (ServiceMode)
        0x07, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,  # "target"
        0x00,  # End target
        # port param only (no alpn)
        0x00, 0x03,  # port key (3)
        0x00, 0x02,  # length 2
        0x01, 0xbb,  # port 443
    ])

    return header + question + svcb_answer


def gen_https_query() -> bytes:
    """
    Generate an HTTPS query.

    RFC9460: HTTPS is SVCB-specific use for HTTP.

    Returns:
        DNS query packet bytes
    """
    query = create_basic_query("example.com", "HTTPS")
    return query.to_wire()


def gen_svcb_multiple_priorities() -> bytes:
    """
    Generate response with multiple SVCB records of different priorities.

    RFC9460 Section 5.2: When omitting SVCB records, prefer lower priority.

    Returns:
        DNS response packet bytes (raw construction)
    """
    header = bytes([
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,
        0x00, 0x03,  # 3 answers
        0x00, 0x00,
        0x00, 0x00,
    ])

    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x40,
        0x00, 0x01,
    ])

    # SVCB with priority 1
    svcb1 = bytes([
        0xc0, 0x0c,
        0x00, 0x40,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x10,
        0x00, 0x01,  # Priority: 1
        0x07, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x31,
        0x00,
        0x00, 0x01, 0x00, 0x02, 0x02, 0x68, 0x32,  # alpn=h2
    ])

    # SVCB with priority 100
    svcb2 = bytes([
        0xc0, 0x0c,
        0x00, 0x40,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x10,
        0x00, 0x64,  # Priority: 100
        0x07, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x32,
        0x00,
        0x00, 0x01, 0x00, 0x02, 0x02, 0x68, 0x32,
    ])

    # SVCB with priority 50
    svcb3 = bytes([
        0xc0, 0x0c,
        0x00, 0x40,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x10,
        0x00, 0x32,  # Priority: 50
        0x07, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x33,
        0x00,
        0x00, 0x01, 0x00, 0x02, 0x02, 0x68, 0x32,
    ])

    return header + question + svcb1 + svcb2 + svcb3


# =============================================================================
# RFC9461 Tests (SVCB Parameters)
# =============================================================================

def gen_svcb_no_alpn() -> bytes:
    """
    Alias for gen_svcb_missing_alpn for RFC9461 specific naming.

    Returns:
        DNS response packet bytes
    """
    return gen_svcb_missing_alpn()


# =============================================================================
# RFC9462 Tests (resolver.arpa)
# =============================================================================

def gen_resolver_arpa() -> bytes:
    """
    Generate a query for resolver.arpa. domain.

    RFC9462 Section 4: resolver.arpa. queries should not be recursively resolved.

    Returns:
        DNS query packet bytes
    """
    query = create_basic_query("resolver.arpa", "A")
    return query.to_wire()


# =============================================================================
# RFC1034 Tests (CNAME/NS/Wildcard)
# =============================================================================

def gen_wildcard_query() -> bytes:
    """
    Generate a query that might match wildcard records.

    RFC1034 Section 4.3.3: Wildcard records with * label should not be cached
    differently.

    Returns:
        DNS query packet bytes
    """
    query = create_basic_query("subdomain.example.com", "A")
    return query.to_wire()


def gen_cname_chain() -> bytes:
    """
    Generate a response with CNAME chain for multilayer redirect test.

    RFC1034 Section 5.2.2: Resolver should handle multiple redirects.

    Returns:
        DNS response packet bytes with CNAME chain (raw construction)
    """
    header = bytes([
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,
        0x00, 0x03,  # 3 answers
        0x00, 0x00,
        0x00, 0x00,
    ])

    question = bytes([
        0x05, 0x73, 0x74, 0x61, 0x72, 0x74,  # "start"
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    ])

    # CNAME: start -> middle
    cname1 = bytes([
        0xc0, 0x0c,
        0x00, 0x05,  # Type CNAME
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x0c,  # RDLEN
        0x05, 0x6d, 0x69, 0x64, 0x64, 0x6c, 0x65,  # "middle"
        0xc0, 0x11,  # pointer to example.com
    ])

    # CNAME: middle -> final
    cname2 = bytes([
        0x05, 0x6d, 0x69, 0x64, 0x64, 0x6c, 0x65,
        0xc0, 0x11,
        0x00, 0x05,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x06,
        0x05, 0x66, 0x69, 0x6e, 0x61, 0x6c,  # "final"
        0xc0, 0x11,
    ])

    # A: final -> 93.184.216.34
    a_record = bytes([
        0x05, 0x66, 0x69, 0x6e, 0x61, 0x6c,
        0xc0, 0x11,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x04,
        0x5d, 0xb8, 0xd8, 0x22,
    ])

    return header + question + cname1 + cname2 + a_record


def gen_cname_loop() -> bytes:
    """
    Generate a response with CNAME loop for error handling test.

    RFC1034 Section 5.2.2: Resolver should return error for resolution loop.

    Returns:
        DNS response packet bytes with CNAME loop (raw construction)
    """
    header = bytes([
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,
        0x00, 0x02,
        0x00, 0x00,
        0x00, 0x00,
    ])

    question = bytes([
        0x05, 0x6c, 0x6f, 0x6f, 0x70, 0x31,  # "loop1"
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    ])

    # CNAME: loop1 -> loop2
    cname1 = bytes([
        0xc0, 0x0c,
        0x00, 0x05,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x06,
        0x05, 0x6c, 0x6f, 0x6f, 0x70, 0x32,  # "loop2"
        0xc0, 0x11,
    ])

    # CNAME: loop2 -> loop1 (creates loop)
    cname2 = bytes([
        0x05, 0x6c, 0x6f, 0x6f, 0x70, 0x32,
        0xc0, 0x11,
        0x00, 0x05,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x06,
        0x05, 0x6c, 0x6f, 0x6f, 0x70, 0x31,
        0xc0, 0x11,
    ])

    return header + question + cname1 + cname2


# =============================================================================
# RFC1035 Tests
# =============================================================================

def gen_authority_response_no_qr() -> bytes:
    """
    Generate a response from authority without QR bit set (malformed).

    RFC1035 Section 7.3: QR bit should be checked when expecting authority
    response.

    Returns:
        DNS packet bytes without QR bit set
    """
    header = bytes([
        0x12, 0x34,
        0x00, 0x00,  # Flags: QR=0 (query) - invalid for response
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
    ])

    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    ])

    answer = bytes([
        0xc0, 0x0c,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x04,
        0x5d, 0xb8, 0xd8, 0x22,
    ])

    return header + question + answer


# =============================================================================
# RFC4025 Tests (IPSECKEY)
# =============================================================================

def gen_ipseckey_gateway_mismatch() -> bytes:
    """
    Generate IPSECKEY record with gateway field mismatching QNAME.

    RFC4025 Section 4.1.2: IPSECKEY gateway not matching QNAME should be
    dropped.

    Returns:
        DNS response packet bytes (raw construction)
    """
    header = bytes([
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
    ])

    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x2b,  # Type IPSECKEY (45)
        0x00, 0x01,
    ])

    # IPSECKEY with gateway different from QNAME
    # Format: precedence(1) gw-type(1) algorithm(1) gateway key
    ipseckey = bytes([
        0xc0, 0x0c,
        0x00, 0x2b,  # Type IPSECKEY
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x20,  # RDLEN
        0x0a,  # Precedence: 10
        0x01,  # Gateway type: 1 (FQDN)
        0x02,  # Algorithm: 2 (DSA)
        0x09, 0x64, 0x69, 0x66, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x74,  # "different"
        0xc0, 0x11,  # pointer to example.com
        # Key (base64 decoded dummy)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c,
    ])

    return header + question + ipseckey


# =============================================================================
# RFC6840 Tests (DNSSEC)
# =============================================================================

def gen_cd_flag_query() -> bytes:
    """
    Generate DNS query with CD (Checking Disabled) flag set.

    RFC6840 Section 5.9: CD flag request should return all relevant records.

    Returns:
        DNS query packet bytes with CD flag
    """
    msg = dns.message.make_query('example.com.', 'A')
    msg.flags |= dns.flags.CD
    return msg.to_wire()


# =============================================================================
# RFC8145 Tests (edns-key-tag)
# =============================================================================

def gen_edns_key_tag_option() -> bytes:
    """
    Generate DNS query with edns-key-tag option.

    RFC8145 Section 4.2.2: Resolver not doing DNSSEC validation should copy
    the option.

    Returns:
        DNS query packet bytes with edns-key-tag
    """
    header = bytes([
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x01,
    ])

    question = bytes([
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    ])

    # edns-key-tag option code is 14
    key_tags = bytes([0x00, 0x01, 0x00, 0x02])
    opt_rdata = bytes([
        0x00, 0x0e,  # Option code: edns-key-tag (14)
        0x00, 0x04,  # Length: 4
    ]) + key_tags

    additional = bytes([
        0x00,
        0x00, 0x29,
        0x04, 0xd0,
        0x00,
        0x00,
        0x00, 0x00,
        0x00, 0x08,
    ]) + opt_rdata

    return header + question + additional


# =============================================================================
# Export all generator functions
# =============================================================================

__all__ = [
    # RFC1123
    'gen_tc_truncated',
    'gen_ttl_zero_response',
    # RFC2308
    'gen_soa_ttl_minimum',
    'gen_negative_response_soa',
    # RFC2930
    'gen_tkey_query',
    # RFC3403
    'gen_naptr_both_fields',
    # RFC6672
    'gen_dname_query',
    'gen_dname_response',
    # RFC6761
    'gen_localhost_aaaa',
    'gen_localhost_a',
    'gen_test_domain_ns',
    'gen_invalid_domain_ns',
    # RFC6891
    'gen_multi_opt_records',
    'gen_opt_non_root_name',
    'gen_badvers_response',
    'gen_opt_invalid_value',
    'gen_edns_version_high',
    # RFC7830
    'gen_multi_padding_options',
    # RFC7686
    'gen_onion_domain',
    # RFC7793
    'gen_shared_address_ptr',
    # RFC8020
    'gen_nxdomain_response',
    # RFC8375
    'gen_home_arpa',
    # RFC8659
    'gen_caa_invalid_issue',
    # RFC8945
    'gen_multi_tsig_records',
    # RFC8914
    'gen_rd_flag_clear',
    # RFC9460
    'gen_svcb_alias_and_service',
    'gen_svcb_alias_with_params',
    'gen_svcb_alias_to_root',
    'gen_svcb_missing_alpn',
    'gen_https_query',
    'gen_svcb_multiple_priorities',
    # RFC9461
    'gen_svcb_no_alpn',
    # RFC9462
    'gen_resolver_arpa',
    # RFC1034
    'gen_wildcard_query',
    'gen_cname_chain',
    'gen_cname_loop',
    # RFC1035
    'gen_authority_response_no_qr',
    # RFC4025
    'gen_ipseckey_gateway_mismatch',
    # RFC6840
    'gen_cd_flag_query',
    # RFC8145
    'gen_edns_key_tag_option',
]