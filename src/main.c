#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <pcap.h>

#define MAX_PACKET_LEN 65535

void handle_packet(uint8_t*_, const struct pcap_pkthdr* header, const uint8_t* data) {
  // TODO: skip header more portably
  data += 16; // advance pointer by 16 to skip the Linux SLL header

  int version = data[0] >> 4;
  printf("IPv%d, %d bytes\n", version, header->len);
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

  // int* dlts;
  // int datalinks_rcode = pcap_list_datalinks(dev, &dlts);
  // if (datalinks_rcode == PCAP_ERROR) {
  //   fprintf(stderr, "Error getting available datalinks: %s\n", pcap_geterr(dev));
  //   return 6;
  // } else {
  //   puts("Supported DLT_ values:");
  //   for (unsigned i = 0; i < datalinks_rcode; ++i) {
  //     printf("  %d\n", dlts[i]);
  //   }
  // }

  // if (pcap_set_datalink(dev, DLT_RAW) == PCAP_ERROR) {
  //   fprintf(stderr, "Error setting raw datalink: %s\n", pcap_geterr(dev));
  //   return 6;
  // }

  printf("Receiving on type-%d link\n", pcap_datalink(dev));
  pcap_loop(dev, -1, handle_packet, NULL);
  puts("Captured 100 packets");
  pcap_close(dev);
}
