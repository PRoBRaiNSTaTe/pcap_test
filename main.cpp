#include <pcap.h>
#include <stdio.h>

int arr[1000];

void dump(const u_char*p, int len)
{
  for(int i=0;i<len;i++)
  {
    arr[i]=*p;
    printf("%02x ",*p);
    p++;
    if((i & 0x0f)==0x0f)
	printf("\n");
  }
	printf("\n");
	if(arr[12]==0x08 && arr[13]==0x00)
	{
	   printf("destination mac: %02X %02X %02X %02X %02X %02X\n",arr[0],arr[1],arr[2],arr[3],arr[4],arr[5]);
        printf("source mac: %02X %02X %02X %02X %02X %02X\n",arr[6],arr[7],arr[8],arr[9],arr[10],arr[11]);
	}
	
	if(arr[14]>=0x40 && arr[14]<=0x4f)
	{
	  printf("Source IP: %02d.%02d.%02d.%02d\n",arr[26],arr[27],arr[28],arr[29]);
	  printf("Destination IP: %02d.%02d.%02d.%02d\n",arr[30],arr[31],arr[32],arr[33]);
	}
	if(arr[23]==0x06)
	{
	  int iplen=arr[16]*16+arr[17];
 	  printf("Source port: %d\n",arr[34]*256+arr[35]);
	  printf("Destination port: %d\n",arr[36]*256+arr[37]);
	  printf("Payload(max:32byte): ");
		for(int i=55;i<87;i++)
		{
		  printf("%02X ",arr[i]);
		  iplen--;
		  if(iplen==40)
		    break;
		}
	  printf("\n");
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
