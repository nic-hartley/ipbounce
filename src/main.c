#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <pcap.h>

#define MAX_PACKET_LEN 65535

void handle_ipv4(unsigned total_len, const uint8_t* data) {
  // TODO: bounds checks

  if (total_len < 20) {
    fprintf(stderr, "Packet too short: %d < 20\n", total_len);
    // not enough space for even a minimal header, wtf
    return;
  }

  unsigned header_len = (data[0] & 0xf) * 4;
  // DSCP, ECN ignored
  unsigned data_len = (data[2] << 8 | data[3]);

  if (data_len != total_len) {
    fprintf(stderr, "Self-reported length doesn't match: %d != %d\n", data_len, total_len);
    return;
  }

  // ID ignored
  // bool evil = data[6] & 0x80; // RFC3514
  // other flags and fragment offset ignored
  unsigned char ttl = data[8];
  unsigned char protocol_num = data[9];
  const char* protocol_name = NULL;
  switch (protocol_num) {
    // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
    case 1: protocol_name = "ICMP"; break;
    case 4: protocol_name = "Packet encapsulation"; break;
    case 6: protocol_name = "TCP"; break;
    case 17: protocol_name = "UDP"; break;
    case 69: protocol_name = "Nice (also SATNET)"; break;
    case 180: protocol_name = "ipbounce setup"; break;
    default: protocol_name = "Something else"; break;
  }
  // skip checksum
  unsigned char source_ip[4] = { data[12], data[13], data[14], data[15] };
  unsigned char dest_ip[4] = { data[16], data[17], data[18], data[19] };

  // ignore options

  printf(
    "IPv4, %d bytes (%d header), "
    "protocol: %s (#%d), "
    "from: %d.%d.%d.%d, "
    "to: %d.%d.%d.%d"
    "\n",
    data_len, header_len,
    protocol_name, protocol_num,
    source_ip[0], source_ip[1], source_ip[2], source_ip[3],
    dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3]
  );
}

void handle_ipv6(unsigned len, const uint8_t* data) {
  puts("IPv6 packet received; not implemented yet");
}

void handle_packet(uint8_t*_, const struct pcap_pkthdr* header, const uint8_t* data) {
  if (header->len != header->caplen) {
    // Not enough buffer space, we didn't get the whole packet. :(
    return;
  }
  // TODO: skip header more portably
  if (header->caplen < 16) {
    // not a full packet?? SLL requires 16 bytes at LEAST
    return;
  }
  data += 16; // advance pointer by 16 to skip the Linux SLL header

  unsigned char version = data[0] & 0xf0;
  if (version == 0x40) {
    handle_ipv4(header->caplen - 16, data);
  } else if (version == 0x60) {
    handle_ipv6(header->caplen - 16, data);
  } else {
    fprintf(stderr, "Unknown IP version: %d\n", version);
    // some other version of IP??
    return;
  }
}

int main() {
  char ERRBUF[PCAP_ERRBUF_SIZE] = {0};

  pcap_t* dev = pcap_create(NULL, ERRBUF);
  if (!dev) {
    fprintf(stderr, "Error loading device: %s\n", ERRBUF);
    return 1;
  } else if (ERRBUF[0]) {
    fprintf(stderr, "Warning loading device: %s\n", ERRBUF);
  }
  pcap_set_snaplen(dev, MAX_PACKET_LEN);
  pcap_set_promisc(dev, 0);
  pcap_set_rfmon(dev, 0);
  pcap_set_timeout(dev, 1000);
  pcap_set_buffer_size(dev, MAX_PACKET_LEN * 10);
  pcap_set_tstamp_type(dev, PCAP_TSTAMP_ADAPTER_UNSYNCED);
  
  int activate_rcode = pcap_activate(dev);
  switch (activate_rcode) {
    case 0:
      puts("Activated device with no warnings");
      break;
    case PCAP_WARNING:
      fprintf(stderr, "Warning activating device: %s\n", pcap_geterr(dev));
      break;
    case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
      fprintf(stderr, "Warning activating device: Timestamp type not supported; caching may break.\n");
      pcap_close(dev);
      break;
    case PCAP_ERROR:
      fprintf(stderr, "Error activating device: %s\n", pcap_geterr(dev));
      pcap_close(dev);
      return 2;
    case PCAP_ERROR_NO_SUCH_DEVICE:
      fprintf(stderr, "Error activating device: 'any' device not found\n");
      pcap_close(dev);
      return 2;
    case PCAP_ERROR_PERM_DENIED:
      fprintf(stderr, "Error activating device: insufficient permission to open device\n");
      pcap_close(dev);
      return 2;
    case PCAP_ERROR_IFACE_NOT_UP:
      fprintf(stderr, "Error activating device: 'any' interface not up\n");
      pcap_close(dev);
      return 2;
    default:
      fprintf(stderr, "Error activating device: Unknown or unexpected return code: %d\n", activate_rcode);
      pcap_close(dev);
      return 2;
  }

  if (pcap_setdirection(dev, PCAP_D_IN) == PCAP_ERROR) {
    fprintf(stderr, "Error setting direction: %s\n", pcap_geterr(dev));
    return 3;
  }

  struct bpf_program compiled;
  if (pcap_compile(dev, &compiled, "ip or ip6", 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
    fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(dev));
    return 4;
  }
  if (pcap_setfilter(dev, &compiled) == PCAP_ERROR) {
    fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(dev));
    return 5;
  }
  pcap_freecode(&compiled);

  int* dlts;
  int datalinks_rcode = pcap_list_datalinks(dev, &dlts);
  if (datalinks_rcode == PCAP_ERROR) {
    fprintf(stderr, "Error getting available datalinks: %s\n", pcap_geterr(dev));
    return 6;
  } else {
    puts("Supported DLT_ values:");
    for (unsigned i = 0; i < datalinks_rcode; ++i) {
      printf("  %d\n", dlts[i]);
    }
  }

  if (pcap_set_datalink(dev, DLT_LINUX_SLL) == PCAP_ERROR) {
    fprintf(stderr, "Error setting hardcoded format: %s\n", pcap_geterr(dev));
    return 7;
  }

  printf("Receiving on type-%d link\n", pcap_datalink(dev));
  pcap_loop(dev, -1, handle_packet, NULL);
  pcap_close(dev);
}
