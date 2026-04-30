// ======== pcap_writer_libpcap.h ========

#ifndef _PCAP_WRITER_LIBPCAP_H_
#define _PCAP_WRITER_LIBPCAP_H_

#include <pcap/pcap.h> // Include libpcap main header file

/**
 * @brief Open a pcap file for writing using libpcap.
 * @param filename The name of the file to create.
 * @return Returns a pcap_dumper_t handle on success, NULL on failure.
 *         This handle needs to be passed along with pcap_t* to the close function.
 */
pcap_dumper_t *pcap_dump_open_for_writing(const char *filename, pcap_t **p_pcap);

/**
 * @brief Write an IP packet to a pcap file.
 * @param dumper The handle returned by pcap_dump_open_for_writing.
 * @param ip_packet Pointer to the IP packet (starting from the IP header).
 * @param len Length of the IP packet.
 */
void pcap_dump_ip_packet(pcap_dumper_t *dumper, const uint8_t *ip_packet, uint32_t len);

/**
 * @brief Close the pcap dumper and associated handles.
 * @param dumper The handle returned by pcap_dump_open_for_writing.
 * @param pcap The pcap_t pointer from pcap_dump_open_for_writing.
 */
void pcap_dump_close_writer(pcap_dumper_t *dumper, pcap_t *pcap);

#endif // !_PCAP_WRITER_LIBPCAP_H_