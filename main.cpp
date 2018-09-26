#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#define ETHER_ADDR_LEN 6
#define tcp_hdr_len_except_payload 20
#define SportLen 2
#define DportLen 2
#define ETHERTYPE_IP  0X0800
#define IPPROTo_TCP 0X06

void mac_print(u_int8_t *p)
{
  for(int i=0;i<(ETHER_ADDR_LEN);i++)
	printf("%02X ",p[i]);
  printf("\n");
}

void data_print(u_int8_t *p,u_int8_t n)
{
  for(u_int8_t i=0;i<n;i++)
	printf("%02X ",p[i]);
  printf("\n");
}

void dump(const u_char*p, int len)
{
  for(int i=0;i<len;i++)
  {
    printf("%02x ",p[i]);
    if((i & 0x0f)==0x0f)
	printf("\n");
  }
	printf("\n");

	struct ethernet_hdr
	{
	  u_int8_t ether_dhost[ETHER_ADDR_LEN];
	  u_int8_t ether_shost[ETHER_ADDR_LEN];
	  u_int16_t ether_type;
	};
	
	struct ipv4_hdr
	{
	  u_int8_t IPverIHL;
	  u_int8_t TOS;
	  u_int16_t IPLen;
	  u_int16_t PacketID;
	  u_int16_t IPFlag;
	  u_int8_t TTL;
	  u_int8_t ProtocolType;
	  u_int16_t IPHeaderChecksum;
	  u_int8_t SIP[4];
	  u_int8_t DIP[4];
	};

	struct tcp_hdr
	{
	  u_int16_t Sport;
	  u_int16_t Dport;
	  u_int8_t TcpInfo[tcp_hdr_len_except_payload-SportLen-DportLen];
	  u_int8_t Payload[32];
	};

	struct ethernet_hdr *eth=(struct ethernet_hdr *)p;
	printf("Source mac: ");
	mac_print(eth->ether_shost);
	printf("Destination mac: ");
	mac_print(eth->ether_dhost);

	if(htons(eth->ether_type)==ETHERTYPE_IP)
	{
	  struct ipv4_hdr *ip=(struct ipv4_hdr *)(p+sizeof(struct ethernet_hdr));
	  printf("Source IP: ");
	  printf("%s\n",inet_ntoa(*(struct in_addr*)&ip->SIP));
	  printf("Destination IP: ");
	  printf("%s\n",inet_ntoa(*(struct in_addr*)&ip->DIP));

		if(ip->ProtocolType==IPPROTO_TCP)
		{
	 	 struct tcp_hdr *tcp=(struct tcp_hdr *)(p+sizeof(struct ethernet_hdr)+sizeof(struct ipv4_hdr));
	 	 printf("Source port: ");
	 	 printf("%d\n",htons(tcp->Sport));
	 	 printf("Destination port: ");
	 	 printf("%d\n",htons(tcp->Dport));
		
		 (htons(ip->IPLen)>=sizeof(struct ipv4_hdr)+sizeof(struct tcp_hdr))? data_print(tcp->Payload,32):data_print(tcp->Payload,32+htons(ip->IPLen)-sizeof(struct ipv4_hdr)-sizeof(struct tcp_hdr));
		}
	}
	printf("\n");
}
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  for(int i=0;i<10;i++) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    dump(packet,header->caplen);
  }

  pcap_close(handle);
  return 0;
}
