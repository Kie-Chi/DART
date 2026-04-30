#ifndef _FAKE_H_
#define _FAKE_H_

#include "common.h"
#include "network.h"
#include "util.h"
#include "dns.h"

#define LARGE_PKT_MAX_LEN 3000
#define DOMAIN_MAX_LEN 256

// Structure for saving check_payload function results
struct chkres {
    uint64_t sum; // Use 64-bit to prevent intermediate sum overflow
    size_t len;
};

// Structure for saving find_str_positions function results
struct findres {
    int* positions; // Dynamic array, storing 1 or 2
    size_t count;
};

size_t _build_std_resp(
    Arena* arena,
    uint8_t *packet,
    size_t packet_len,
    char *qname,
    char *prefix,
    char *victim,
    char *origin_ip,
    size_t length);

size_t build_fake_resp(
    Arena* arena,
    uint8_t *packet,
    size_t packet_len,
    char *qname,
    char *prefix,
    char *victim,
    char *origin_ip,
    char *attacker,
    char *fake_ip,
    size_t length);

#endif