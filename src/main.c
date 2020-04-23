#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <pcap.h>

#define MAX_PACKET_LEN 65535

const char* get_protocol_name(unsigned char num) {
  switch (num) {
    // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
    // (and I'm claiming 180)
    case 1: return "ICMP";
    case 4: return "Packet encapsulation";
    case 6: return "TCP";
    case 17: return "UDP";
    case 69: return "Nice (also SATNET)";
    case 253: return "ipbounce setup";
    default: return "Something else";
  }
}

void handle_ipv4(unsigned total_len, const uint8_t* packet) {
  // TODO: bounds checks

  if (total_len < 20) {
    fprintf(stderr, "Packet too short: %d < 20\n", total_len);
    // not enough space for even a minimal header, wtf
    return;
  }

  unsigned header_len = (packet[0] & 0xf) * 4;
  // DSCP, ECN ignored
  unsigned payload_len = packet[2] << 8 | packet[3];

  if (payload_len != total_len) {
    fprintf(stderr, "Reported length doesn't match: %d != %d\n", payload_len, total_len);
    return;
  }

  // bool evil = data[6] & 0x80; // RFC3514
  unsigned char ttl = packet[8];
  unsigned char protocol_num = packet[9];

  const unsigned char* source_ip = &packet[12];
  const unsigned char* dest_ip = &packet[16];

  // ignore options

  printf(
    "IPv4, %d bytes (%d header), "
    "protocol: %s (#%d), "
    "from: %d.%d.%d.%d, "
    "to: %d.%d.%d.%d"
    "\n",
    payload_len, header_len,
    get_protocol_name(protocol_num), protocol_num,
    source_ip[0], source_ip[1], source_ip[2], source_ip[3],
    dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3]
  );
}

void handle_ipv6(unsigned total_len, const uint8_t* packet) {
  if (total_len < 40) {
    fprintf(stderr, "Packet too short: %d < 20\n", total_len);
    // not enough space for even a minimal header, wtf
    return;
  }
  unsigned payload_len = packet[4] << 8 | packet[5];
  if (payload_len != total_len) {
    fprintf(stderr, "Reported length doesn't match: %d != %d\n", payload_len, total_len);
  }
  
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
