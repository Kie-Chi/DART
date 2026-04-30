// ======== pcap_writer_libpcap.c ========
#include "pcap_writer.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

pcap_dumper_t* pcap_dump_open_for_writing(const char* filename, pcap_t** p_pcap) {
    // libpcap requires a pcap_t handle as context for writing to a file
    // DLT_RAW means we directly provide raw IP packets, no link-layer header
    pcap_t* pcap = pcap_open_dead(DLT_RAW, 65535);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_dead() failed\n");
        return NULL;
    }

    pcap_dumper_t* dumper = pcap_dump_open(pcap, filename);
    if (dumper == NULL) {
        fprintf(stderr, "pcap_dump_open() failed: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        return NULL;
    }

    *p_pcap = pcap; // Return the pcap_t handle to the caller for later closing
    return dumper;
}

void pcap_dump_ip_packet(pcap_dumper_t* dumper, const uint8_t* ip_packet, uint32_t len) {
    if (!dumper || !ip_packet || len == 0) {
        return;
    }

    struct pcap_pkthdr header;
    struct timeval tv;
    gettimeofday(&tv, NULL);

    header.ts.tv_sec = tv.tv_sec;
    header.ts.tv_usec = tv.tv_usec;
    header.caplen = len; // Captured length
    header.len = len;    // Original length

    pcap_dump((u_char*)dumper, &header, ip_packet);
}

void pcap_dump_close_writer(pcap_dumper_t* dumper, pcap_t* pcap) {
    if (dumper) {
        pcap_dump_close(dumper);
    }
    if (pcap) {
        pcap_close(pcap);
    }
}