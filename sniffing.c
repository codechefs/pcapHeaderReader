

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
typedef struct arphdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
}arphdr_t;

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void hex_to_ascii(const u_char *payload, int len, int offset);

FILE *fp;
void hex_to_ascii(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
        //fprintf(fp,"%05d",offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
	//	fprintf(fp,"%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7){
			printf(" ");
	//		fprintf(fp," ");
}
			
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
        {
		printf(" ");
	//	fprintf(fp," ");
	}
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
	//		fprintf(fp,"   ");
		}
	}
	printf("   ");
        //fprintf(fp,"    ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
                {
			printf("%c", *ch);
			fprintf(fp,"%c",*ch);
		}
		else
		{
			printf(".");
			fprintf(fp,".");
		}

		ch++;
	}

	printf("\n");


return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			
	int line_len;
	int offset = 0;				
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		hex_to_ascii(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		hex_to_ascii(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			hex_to_ascii(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	arphdr_t *arpheader = NULL;       /* Pointer to the ARP header              */ 	
	int size_ip;
	int size_tcp;
	int size_payload;
        int last;
        int i;
	
	printf("\n************Packet number %d*****************\n", count);
        fprintf(fp,"\n\n***************Packet Number %d:****************",count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);
		//return;
                goto last;
	}

	/* print source and destination IP addresses */
	printf("From: %s\n", inet_ntoa(ip->ip_src));
	printf("To: %s\n", inet_ntoa(ip->ip_dst));
	fprintf(fp,"\nFrom: %s", inet_ntoa(ip->ip_src));
	fprintf(fp,"\nTo: %s", inet_ntoa(ip->ip_dst));	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
			fprintf(fp,"\nProtocol: TCP");
			break;
		case IPPROTO_UDP:
			printf("Protocol: UDP\n");
			fprintf(fp,"\nProtocol: UDP");
			return;
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\n");
			fprintf(fp,"\nProtocol: ICMP");
			return;

		case IPPROTO_IP:
			printf("Protocol: IP\n");
			fprintf(fp,"\nProtocol: IP");
			return;
		default:
			printf("Protocol: unknown\n");
			fprintf(fp,"\nProtocol: TCP");
			return;
	}
	

	
	/*compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {

		//printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		//fprintf(fp,"\n* Invalid TCP header length: %u bytes", size_tcp);
		//return;
                goto last;
	}
	
	printf("Src port: %d\n", ntohs(tcp->th_sport));
	printf("Dst port: %d\n", ntohs(tcp->th_dport));
	
	fprintf(fp,"\nSrc port: %d", ntohs(tcp->th_sport));
	fprintf(fp,"\nDst port: %d", ntohs(tcp->th_dport));
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data;
	 */
	if (size_payload > 0) {
		printf("Payload (%d bytes):\n", size_payload);
		fprintf(fp,"\nPayload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}
        fprintf(fp,"\n");
return;

//If it is arp packet then
last:
  arpheader = (struct arphdr *)(packet+14); /* Point to the ARP header */  
  printf("\n\nOperation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply"); 
  printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown"); 
  printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown"); 

  fprintf(fp,"\n\nOperation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply"); 
  fprintf(fp,"Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown"); 
  fprintf(fp,"Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown"); 


 /* If is Ethernet and IPv4, print packet contents */ 
  if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800)
  { 
    printf("Sender MAC: "); 
    fprintf(fp,"Sender MAC: "); 
    for(i=0; i<6;i++)
    {
        printf("%02X:", arpheader->sha[i]); 
        fprintf(fp,"%02X:", arpheader->sha[i]); 
    }

    printf("\nSender IP: "); 
    fprintf(fp,"\nSender IP: ");
    for(i=0; i<4;i++)
    {
        printf("%d.", arpheader->spa[i]); 
        fprintf(fp,"%d.", arpheader->spa[i]); 
    }

    printf("\nTarget MAC: "); 
    fprintf(fp,"\nTarget MAC: "); 
    for(i=0; i<6;i++)
    {
        printf("%02X:", arpheader->tha[i]); 
        fprintf(fp,"%02X:", arpheader->tha[i]);     
    }
    printf("\nTarget IP: "); 
    fprintf(fp,"\nTarget IP: "); 

    for(i=0; i<4; i++)
    {
        printf("%d.", arpheader->tpa[i]); 
        fprintf(fp,"%d.", arpheader->tpa[i]); 
    }
  }
}

int main()
{

	char dev[20] ;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	fp=fopen("result.txt","w");
        //dev=argv[1];
        printf("\nEnter pcap file name : ");
        scanf("%s",dev);
        handle=pcap_open_offline(dev,errbuf);
        if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}



	/* call back function */
	pcap_loop(handle,0, process_packet, NULL);
	printf("\nCapture complete.\n");
	printf("\nExtracted data is saved in 'Result.txt'\n");
        fclose(fp);  
return 0;
}

