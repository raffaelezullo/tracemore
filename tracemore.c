/*
Tracemore
RAFFAELE ZULLO
2020
*/

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>

#ifndef _BSD_SOURCE
#define _BSD_SOURCE            1
#endif
#ifdef _NO_GETADDRINFO
#include "libs/ifa/ifaddrs.h"
#endif
#ifndef _NO_GETADDRINFO
#include <ifaddrs.h>
#endif

#include "tracemore.h"

#include <memory.h>
#include <stdbool.h>
#include <asm/byteorder.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "libs/sha/sha1.h"


// vars
int sndsock;
int rcvsock;
int sndsock6;
int sndsock6b; // only for receive tcp udp answers
int rcvsock6;
int sndsocku;
fd_set readfds;
int max_sd;
int raw_sockets_created = 0;
int got_ifaddrs = 0;
int new_ifaddrs = 0;
int if_custom_name = 0;
int if_custom_addr = 0; 
char if_custom_name_string [20] = "";
char if_custom_addr_string [50] = "";
int use_eth_sock=0;
int delay = 0;
int tb_delay = 0;
int nr_tb_packet = 0;
int nr_tb_hide = 0;
int nr_keep_port=0;
int nr_keeped_port=-1;
int nr_custom_port=0;
int nr_port=-1;
struct sockaddr_in dst;  // added 
struct sockaddr_in dst2;  // added 
struct sockaddr_in6 dst6 = { 0 };
struct sockaddr_in6 dst26 = { 0 };
struct sockaddr_in dstu;  // added 
struct sockaddr_in dstu2;  // added

socklen_t dst2len= 16;
socklen_t dst26len = 28;
socklen_t dstu2len= 16;
len_and_sockaddr *dest_lsa;
int packlen;                     /* total length of packet */
int pmtu;                       /* Path MTU Discovery (RFC1191) */
uint32_t ident;
uint16_t port; // 32768 + 666;  /* start udp dest port # for probe packets */
int waittime; // 5;             /* time to wait for response (in seconds) */
unsigned char sent_datagram[DATAGRAM_SIZE]; // SENT
unsigned char syn_sent_datagram[DATAGRAM_SIZE]; // SENT
unsigned char recv_pkt[DATAGRAM_SIZE];    /* last inbound (icmp) packet */
unsigned char mod_pkt[DATAGRAM_SIZE];	// packet to store modifidications occurred so far
unsigned char mod_pkt_msk [DATAGRAM_SIZE];	// mask to know where modifications occurred
unsigned char custom_pkt [DATAGRAM_SIZE];	// mask to store custom fields value
unsigned char custom_pkt_msk [DATAGRAM_SIZE];	// mask to know custom fields
unsigned char answer_pkt[DATAGRAM_SIZE]; 	// recevied tcp or udp answer packet
int answer_len=0;
unsigned char nr_answer_pkt[DATAGRAM_SIZE]; 	// recevied tcp or udp answer packet
int nr_answer_len = -1;
unsigned char default_pkt[200]; 

unsigned char answer_text[ANSWER_TEXT_SIZE]; 	// tracebox text received from server 
unsigned char built_pkt[DATAGRAM_SIZE]; 		// packet sent via non raw socket 
unsigned char pay_packet [DATAGRAM_SIZE]; // SENT

// layer 3 and 4 headers and payload, http header and payload
unsigned char sent_ip_bytes [100];
unsigned char sent_tcp_bytes [60];
unsigned char sent_udp_bytes [8];
unsigned char sent_pay_bytes [DATAGRAM_SIZE] ;
unsigned char sent_http_headers_bytes [DATAGRAM_SIZE];
unsigned char sent_http_pay_bytes [DATAGRAM_SIZE];

unsigned char rec_ip_bytes [100];
unsigned char rec_tcp_bytes [60];
unsigned char rec_udp_bytes [8];
unsigned char rec_pay_bytes [DATAGRAM_SIZE] ;
unsigned char rec_http_headers_bytes [DATAGRAM_SIZE];
unsigned char rec_http_pay_bytes [DATAGRAM_SIZE];

unsigned char mod_ip_bytes [100];
unsigned char mod_tcp_bytes [60];
unsigned char mod_udp_bytes [8];
unsigned char mod_pay_bytes [DATAGRAM_SIZE] ;
unsigned char mod_http_headers_bytes [DATAGRAM_SIZE];
unsigned char mod_http_pay_bytes [DATAGRAM_SIZE];

unsigned char mask_ip_bytes [100];
unsigned char mask_tcp_bytes [60];
unsigned char mask_udp_bytes [8];
unsigned char mask_pay_bytes [DATAGRAM_SIZE] ;
unsigned char mask_http_headers_bytes [DATAGRAM_SIZE];
unsigned char mask_http_pay_bytes [DATAGRAM_SIZE];

unsigned char custom_ip_bytes [100];
unsigned char custom_tcp_bytes [60];
unsigned char custom_udp_bytes [8];
unsigned char custom_pay_bytes [DATAGRAM_SIZE] ;
unsigned char custom_http_headers_bytes [DATAGRAM_SIZE];
unsigned char custom_http_pay_bytes [DATAGRAM_SIZE];

unsigned char custom_mask_ip_bytes [100];
unsigned char custom_mask_tcp_bytes [60];
unsigned char custom_mask_udp_bytes [8];
unsigned char custom_mask_pay_bytes [DATAGRAM_SIZE] ;
unsigned char custom_mask_http_headers_bytes [DATAGRAM_SIZE];
unsigned char custom_mask_http_pay_bytes [DATAGRAM_SIZE];

unsigned char answer_ip_bytes [100];
unsigned char answer_tcp_bytes [60];
unsigned char answer_udp_bytes [8];
unsigned char answer_pay_bytes [DATAGRAM_SIZE] ;
unsigned char answer_http_headers_bytes [DATAGRAM_SIZE];
unsigned char answer_http_pay_bytes [DATAGRAM_SIZE];

// pointers to headers
struct iphdr * sent_ip = ((struct iphdr *) sent_datagram);
	struct my_ipv6_hdr * sent_ip6 = ((struct my_ipv6_hdr *) sent_datagram);
struct tcphdr_mss * tcp_header = (struct t *) (sent_datagram + sizeof (struct iphdr)   );
struct udphdr * udp_header = ((struct udphdr *) ( sent_datagram + 20 ));
struct my_icmphdr * icmp_header = ((struct my_icmphdr *) ( sent_datagram + 20 ));
int tcp_header_len = 20;
int ip_header_len = 20;
int payload_len = 0;
int udp_trailer_len = 0;
int last_sent_len = -1;
struct tcphdr * sent_tcp = ( (struct tcphdr *) (sent_datagram + sizeof (struct iphdr)   ) );
struct udphdr * sent_udp = ((struct udphdr *) ( sent_datagram + 20 ));
struct my_icmphdr * sent_icmp = ((struct my_icmphdr *) ( sent_datagram + 20 ));
// received
struct iphdr * rec_ip = ((struct iphdr *) &recv_pkt[28]);
	struct my_ipv6_hdr * rec_ip6 = ((struct my_ipv6_hdr *) &recv_pkt[8] );
struct tcphdr * rec_tcp = (struct t *) (&recv_pkt[28] + sizeof (struct iphdr)   );
struct udphdr * rec_udp = ((struct udphdr *) ( &recv_pkt[28] + 20 ));
struct my_icmphdr * rec_icmp = ((struct my_icmphdr *) ( &recv_pkt[28] + 20 ));
// modded
struct iphdr * mod_ip = ((struct iphdr *) mod_pkt);
struct tcphdr * mod_tcp = (struct t *) (mod_pkt + sizeof (struct iphdr)   );
struct udphdr * mod_udp = ((struct udphdr *) (mod_pkt + 20 ));
struct my_icmphdr * mod_icmp = ((struct my_icmphdr *) (mod_pkt + 20 ));
// mask
struct iphdr * mask_ip = ((struct iphdr *) mod_pkt_msk);
struct tcphdr_mss * mask_tcp = (struct t *) (mod_pkt_msk + sizeof (struct iphdr)   );
struct udphdr * mask_udp = ((struct udphdr *) ( mod_pkt_msk + 20 ));
struct my_icmphdr * mask_icmp = ((struct my_icmphdr *) ( mod_pkt_msk + 20 ));

// custom fields
struct iphdr * custom_ip = ((struct iphdr *) custom_pkt);
		struct my_ipv6_hdr * custom_ip6 = ((struct my_ipv6_hdr *) custom_pkt);
struct tcphdr_mss * custom_tcp = (struct t *) (custom_pkt + sizeof (struct iphdr)   );
struct udphdr * custom_udp = ((struct udphdr *) ( custom_pkt + 20 ));
struct my_icmphdr * custom_icmp = ((struct my_icmphdr *) ( custom_pkt + 20 ));

// custom fields mask
struct iphdr * custom_mask_ip = ((struct iphdr *) custom_pkt_msk);
	struct my_ipv6_hdr * custom_mask_ip6 = ((struct my_ipv6_hdr *) custom_pkt_msk);
struct tcphdr_mss * custom_mask_tcp = (struct t *) (custom_pkt_msk + sizeof (struct iphdr)   );
struct udphdr * custom_mask_udp = ((struct udphdr *) ( custom_pkt_msk + 20 ));
struct my_icmphdr * custom_mask_icmp = ((struct my_icmphdr *) ( custom_pkt_msk + 20 ));

// answer
struct iphdr * answer_ip = ((struct iphdr *) answer_pkt);
	struct my_ipv6_hdr * answer_ip6 = ((struct my_ipv6_hdr *) answer_pkt);
struct tcphdr_mss * answer_tcp = (struct t *) (answer_pkt + sizeof (struct iphdr)   );
struct udphdr * answer_udp = ((struct udphdr *) ( answer_pkt + 20 ));
struct my_icmphdr * answer_icmp = ((struct my_icmphdr *) ( answer_pkt + 20 ));

    
// times
struct timeval t1, t2;

// command
char* this_command;
char local_addr[50];              
char dest_addr[50];               

/* ANALYSE DATA */
struct iphdr *sent_ip;
struct iphdr *quoted_ip;
int quoted_ip_offset;
int quoted_tcp_offset=48;
bool partial;
int ttl;
int seq;

// flags due to input parameters
int prot = 6;
int prot3 = 4;
int new_prot3 = 0;
int dropped_rst = 0;
int off_drop_rst = 0;

int off_ipcheck = 0;	 
int off_tcpcheck = 0;	 
int off_udpcheck = 0;	 
int off_icmpcheck = 0;	 

int off_iplen  = 0;
int off_tcplen  = 0;
int off_udplen  = 0;

int udpcheck_len_only = 0;
int udpcheck_ippay = 0;
int udpcheck_3rd = 0;
int udpcheck_4th = 0;
uint16_t udpcheck_add = 0;

int cst_ttl = 0;
int off_tcp_pad =0;
int increase_port =0;

int show_ms = 0;
int show_quoted_len = 0;
int wayback_ttl = 0;
int print_0 = 1;
int print_if = 0;
int print_last_sent = 0;
int print_last_recv = 0;
int no_icmp_info = 0;

int compare_default=0;
int dest_ip = 0;
int dest_udp = 0;
int dest_tcp = 0;
int dest_opt = 0;
int dest_ecn = 0;
int dest_ack = 0;
int dest_pay = 0;
int dest_pay_1 = 0;
int dest_pay_printable = 0;
int dest_pay_choice = 0;
int pay_as_text = 0;
int pay_as_hex = 0;
int show_all_opt =0;
int hide_opt_val=0;
int hide_opt_changed=0;
int hide_all_opt_changed=0;
int hide_pay=0;

// custom input parameters
int ttl_min=1;
int ttl_max=64;
int row_stars = 3;
int max_stars= 10;
int skip_ttl = -1;
int repeat = 1;
int star_timeout = 3000000;
int recv_only = 0;
int keep_session = 0;
int avoid_retr = 0;
int dont_increase_seq = 0;
int ack_ad_libitum = 0;
int debug_random_mod = 0;
int icmp_du_as_te = 0;
int mp_checksum=1;
int mp_checksum_wrg=0;
char  * mptcp_dss_option;
int mptcp_dss_option_present = 0;

// flags for traceroute only for NR
int tr_udp_nr = 0;
int tr_ping_nr = 0;
int repeat_tr_ping_nr = 1;
int repeat_tr_udp_nr = 1;
int increase_port_tr_udp_nr = 0;

// flags due to custom params
// IP
int c_dscp = 0;
int c_ecn = 0;
int c_flags_res = 0;
int c_flags_df = 0;
int c_flags_mf = 0;

// values for custom params
uint8_t v_ttl;
int v_flags_res = 0;
int v_flags_df = 0;
int v_flags_mf = 0;
int v_dscp = 0;
int v_ecn = 0;


// offsets between actual and correct checksums
uint16_t ipcheck_wrg = 0;
uint16_t tcpcheck_wrg = 0;
uint16_t udpcheck_wrg = 0;
uint16_t icmpcheck_wrg = 0;

// wrong length values
int tcphl_wrg = 5;	

// other flags
first_probe = 1;

// icmp flags
int icmp_4884_length=0;
uint32_t  icmp_unused = 0;
int icmp_is_multipart= 0;
int icmp_multipart_start_at= 0;

// port
int dest_port = 80;

// session parameters
unsigned char saved_seq[4]={0,0,0,0};
unsigned char saved_ack_seq[4]={0,0,0,0};
unsigned char saved_flags=0;
// TCP OPTION Multipath
int mp_cap_syn_ack = 0;
uint64_t mp_cap_syn_ack_key = 0;
// TCP OPTION FAST OPEN
int fo_cookie_len = 4;
unsigned char fo_cookie [16];

// custom fields
char ** custom_fields;
int custom_fields_count = 0;

// NR params 
int nr = 0;
int nr_tb = 0;
int nr_tb_doing = 0;
int print_nr_tb = 0;
char tb_params_string[500];

int nr_prot4 = 6;
int nr_dest = 80;
int nr_source = 20000;
char tb_serv_addr[50] = "0.0.0.0";	// tbs parameter needed
char tb_serv_addr6[50] = "::";		// tbs parameter needed
char client80_addr[50] = "";
int nr_client80=0;
int serv_to = 10;
int nr_serv_to =0;
int nr_back = 0;
int nr_back_icmp = 0;
int nr_syncnt = -1;
int nr_print_synack=1;
int nr_print_payack=1;
int nr_print_syn=0;
int nr_print_pay_back=0;
int nr_test_fo=0;
int nr_back_opt = 0;
char nr_back_options[1000] = "";
char nr_ack_options[1000] = "";
int nr_ack_opt = 0;
int nr_tcp_pay = 0;
int nr_tcp_no_pay=0;
int nr_forward_sack = 0;
int nr_tcp_fo = 0;
int nr_tcp_md5 = 0;
int nr_tcp_urg = 0;
int nr_tcp_mss = 1460;		// correct if IPv6 !!!
int nr_tcp_rcvbuf = -1;
int nr_tcp_coalesc = 0;
int nr_frag = 0;
int nr_frag_mf = 0;
// ip
int nr_ttl = -1;
int nr_extimated_ttl = 0;
int nr_tos = 0;
int nr_df = 0;
int nr_mf = 0;
// ip6
int nr_hl = -1;
int nr_tc = 0;


// nr packets 
int nr_dest_got=0;
int nr_source_got=0;
int nr_tcp_synack_got = 0;
int nr_tcp_window_got=0;
int nr_tcp_window_reliable = 1;
int nr_tcp_urgptr_got=0;
int nr_tcp_doff_got=0;
uint16_t nr_tcp_mss_got = 0;
int nr_tcp_mss_back_got = 0;
int nr_tcp_ws=-1;
int nr_tcp_ws_reliable = 0;
int nr_tcp_ws_back_got = 0;
int nr_tcp_ws_got=0;
int nr_tcp_ts_got=0;
int nr_tcp_sack_perm_got=0;
int nr_tcp_mss_tcpi=0;
int nr_tcp_ws_tcpi=0;
int nr_tcp_ts_tcpi=0;
int nr_tcp_sack_perm_tcpi=0;
int nr_tcp_syn_data_acked_tcpi=0;
int nr_tcp_fo_got=0;
int nr_tcp_md5sig_got=0;
int nr_udpcheck_got=0;
int nr_tcp_opt_cd = 0;
int nr_tcp_payack_got=-1;
// ip
int nr_ttl_got = 1;
int nr_tos_got = 0;
int nr_df_got = 0;
int nr_mf_got = 0;
// ip6
int nr_hl_got = 0x40;
int nr_tc_got = 0;

// NR sockets
int nr_tcp_sock = 0;
int nr_udp_sock = 0;
int nr_sndsock = 0;

// NR timing parameters and variables
int NR_TRACEBOX_BACK_TIMEOUT=60;
int NR_SENT_PACKET_TIMEOUT=10;
int nr_tracebox_back_ended=0;

// SR
int sr=0;

// SE
int se=0;
int se_sndsock = 0;
int se_prot3 = 4;
int se_prot4 = 6;
int se_dest = 80;
int se_syncnt = 1;
int se_ttl=64;
int se_ttl_got=-1;
int se_increase_ttl=0;


// UDPO
int se_udpo_sndsock = 0;
int se_udpo=0;
int SE_UDPO_TIMEOUT=5;



bool anydiff( char* a , char* b, int len) {	
	
	
	for (int i=0; i<1; i++) {
		if ( (char)(a[i]) != (char)(b[i]) )
			return 1;
	}
	return 0;
}

bool any( char* a, int len) {	
	for (int i=0; i<len; i++) {
		//printf(" %c " , a[i]);fflush(stdout);
		if ( a[i] != 0  )
			return 1;
	}
	return 0;
}

void copy( char* a, char* b, int len) {	
	for (int i=0; i<len; i++) {
		if ( a[i] != b[i] )
			return 1;
	}
}


uint32_t mptcp_sha1hash (uint64_t u) {
	SHA_CTX sha; 
	int n = 8;	
	unsigned char results[20];
	SHA1_Init(&sha); 
	SHA1_Update(&sha, (unsigned char *)&u, n); 
	SHA1_Final(results, &sha); 
	uint32_t* ret = &results;
	return *ret;
}

// flip uint16_t (for current UDP OCS)
uint16_t flip_bytes_uint16t ( uint16_t u ) {
	int hi = (u & 0xff00) >> 8;
	int lo = (u & 0xff);
	return  lo  << 8 | hi;
}

int get_ifaddrs() {

	// GET INTERFACE ADDRESS	
	struct ifaddrs *addrs, *tmp;
	getifaddrs(&addrs);
	tmp = addrs;

	int family = 0;
	if ( prot3 == 4 )
		family = AF_INET;
	else if ( prot3 == 6 )
		family = AF_INET6;

    // otherwise define _GNU_SOURCE 
    char host[NI_MAXHOST];
	

	while (tmp) {
		
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == family) { 

			struct sockaddr_in * sa;
			char str[INET_ADDRSTRLEN];
			memset (str, 0, INET_ADDRSTRLEN);
			struct sockaddr_in6* sa6;
			char str6[INET6_ADDRSTRLEN];
			memset (str6, 0, INET6_ADDRSTRLEN);

			if ( prot3 == 4 ) {
				sa = (struct sockaddr_in *) tmp->ifa_addr;
				inet_ntop(AF_INET, &(sa->sin_addr), str, INET_ADDRSTRLEN);
				memcpy(local_addr, str, strlen(str));
				local_addr[strlen(str)]='\0';
			}

			else if ( prot3 == 6 ) {
				sa6 = (struct sockaddr_in6 *) tmp->ifa_addr;
				inet_ntop(AF_INET6, &(sa6->sin6_addr), str6, INET6_ADDRSTRLEN);
				memcpy(local_addr, str6, strlen(str6));
				local_addr[strlen(str6)]='\0';
			}

			if ( print_if )			
				printf("%s: %s\n", tmp->ifa_name, local_addr);

			// check if custom 
			if ( if_custom_name ) {
				if (strcmp(if_custom_name_string, tmp->ifa_name) == 0) 
						break;
			}
			else if ( if_custom_addr ) {
				if (strcmp(if_custom_addr_string, local_addr) == 0) 
						break;
			}
			// check if it's not localhost
			else {
				if ( prot3 == 4 ) {
					if (strcmp(local_addr,"0.0.0.0") && strcmp(local_addr,"127.0.0.1")) 
						break;
				}
				else if  ( prot3 == 6 )
					if (strcmp(local_addr,"::1") && strncmp(local_addr,"fe80",4)) 
						break;
			}
		}
		tmp = tmp->ifa_next;
    	}

    freeifaddrs(addrs);
	return 1;
}

int create_raw_sockets() {
	// IPv4
	if ( prot3 == 4 ) {
		// TCP RAW SOCKET SEND
		sndsock = socket(AF_INET, SOCK_RAW, prot);

		if (sndsock < 0)
		{
		    printf("ERROR opening raw send socket\n");
		    return 0;
		} 
	
		int hdrincl=1;
		if (setsockopt(sndsock,IPPROTO_IP,IP_HDRINCL,&hdrincl,sizeof(hdrincl))<0) {
			printf("ERRROR IP_HDRINCL,\n");            
			return 0;    // it was printf("setsockopt %s ",strerror(errno));
		}
		
	// changing proto or rcvsock      
	if ( use_eth_sock )
		rcvsock = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));			
	else 
		rcvsock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);	
	
	if (rcvsock < 0)
		{
		    printf("ERROR opening raw receive socket\n");
		    return 0;
		}
	}
	
	// IPv6
	else if ( prot3 == 6 )  {
 		sndsock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
		if (sndsock6 < 0)
		{
		    printf("ERROR opening raw send socket\n");
		    return 0;
		} 

		//int hdrincl=1;
		// if (setsockopt(sndsock6,IPPROTO_IP,IP_HDRINCL,&hdrincl,sizeof(hdrincl))<0) {
			// printf("setsockopt nope\n");            
			//return 0;    // it was printf("setsockopt %s ",strerror(errno));
		//}

	  	// ICMP RAW SOCKET RECEIVE      
		rcvsock6 = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);	
		if (rcvsock < 0)
		{
		    printf("ERROR opening raw receive socket\n");
		    return 0;
		}
		
		// TCP UDP raw socket (bis) to receive only
		sndsock6b = socket (AF_INET6, SOCK_RAW, prot);	
		if (rcvsock < 0)
		{
		    printf("ERROR opening raw receive socket\n");
		    return 0;
		}
	}

	// raw sockets created successfully
	return 1;
}

int compare_in6_addr ( struct in6_addr  a, struct in6_addr b) {
	uint32_t * a32;
	uint32_t * b32;
	int result = 0;
	for ( int i=0; i<4; i++) {
		a32 =  ((uint32_t *) &a) +i;
		b32 =  ((uint32_t *) &b) +i;
		if (*a32 != *b32)	
			result = 1;
	}
	return result;
}


void set_in6_addr(struct in6_addr * a, uint32_t b[4]) {
	uint32_t * a32;
	uint32_t * b32;
	int result = 0;
	for ( int i=0; i<4; i++) {
		a32 =  ((uint32_t *) a) +i;
		b32 =  ((uint32_t *) b) +i;
		*a32 == *b32;
	}
}

int copy_in6_addr ( struct in6_addr * a, struct in6_addr * b) {
	uint32_t * a32;
	uint32_t * b32;
	int result = 0;
	for ( int i=0; i<4; i++) {
		a32 =  ((uint32_t *) a) +i;
		b32 =  ((uint32_t *) b) +i;
		*a32 = *b32;
	}
}


int compare_field ( char* sent, char* rec, char* mod, char* mask, int len) {	
	bool modded = any(mask, len);		// check if the field has been already modified
	if 	( !modded && (memcmp( sent, rec, len) != 0) ) {
			return 1;
	} else if ( modded  &&  (memcmp( mod, rec, len)!= 0) ) {
		return 2;
	}
	else {
		return 0;	
	}
}

void store_field ( char* sent, char* rec, char* mod, char* mask, int len, int c) {
	if (c == 1) {
		mask[0] = 1;			// the field has been modified
		memcpy( mod, rec, len);	// store the field modified so far
	} else if ( c == 2 ) {
		memcpy( mod, rec, len);	// store the field modified so far
	}

}

char * rz_ntoa ( struct in_addr in ) {
	uint8_t * a;
	a =  &in;
	char* c = malloc(sizeof(char) * 20);   
	sprintf (c, "%d.%d.%d.%d", *(a), *(a+1), *(a+2), *(a+3)); 
	// printf("%s\n", c);
	return c;
}

long  rand_long_int () {
	struct timeval t;
	long int t_usec;
	gettimeofday(&t, NULL);
	t_usec = t.tv_usec + 1000000 * t.tv_sec;
	srand(t_usec);
	return rand();
}

void parse_custom_value ( char* value, int* val, int* def ) {
	if ( strncmp (value, "-", 1 ) == 0 ) {
			*val = 0;
			*def = 1;
		} else if ( sscanf(value, "0x%x", val ) == 1 ) {

		} else if ( sscanf(value, "%d", val ) == 1 ) {

		} else if ( strncmp(value, "rand", 4) == 0 ) {
			*val = rand_long_int();
		} else {
			*val = 0;
		}
}

static len_and_sockaddr* dup_sockaddr(const len_and_sockaddr *lsa) {
	len_and_sockaddr *new_lsa = malloc(LSA_LEN_SIZE + lsa->len);
	memcpy(new_lsa, lsa, LSA_LEN_SIZE + lsa->len);
	return new_lsa;
}

static uint16_t ip_checksum(void* vdata,size_t length) {
         unsigned long sum = 0;
         const uint16_t *ip1;
 
         ip1 = vdata;
         while (length > 1) {                 
		 sum += *ip1++;
                 if (sum & 0x80000000)
                         sum = (sum & 0xFFFF) + (sum >> 16);
                 length -= 2;
         }

         while (sum >> 16)
                 sum = ( sum & 0xFFFF) + (sum >> 16);
 
         return(~sum);
}


// Generic checksum calculation function
static unsigned short csum(unsigned short *buf, int nwords) {      
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// This function casts an IP packet from an char *
static struct iphdr * castToIP(char datagram[], int offset) {    
    struct iphdr *ip;
    ip = (struct iphdr *) (datagram + offset);

    return ip;
}

// This function casts an ICMP packet from an char *
static struct icmp * castToICMP(char datagram[], int offset) {
    struct icmp *icmp;
    icmp = (struct icmp *) (datagram + offset);

    return icmp;
}

// This function casts a TCP packet from an char *
static struct tcphdr * castToTCP(char datagram[], int offset) {
    struct tcphdr *tcp;
    tcp = (struct tcphdr *) (datagram + offset);
    return tcp;
}
static uint16_t transport_checksum(const void *buff, size_t len, in_addr_t src_addr,  in_addr_t  dest_addr) {
	return transport_checksum_custom(buff, len, len, src_addr, dest_addr);
}

static uint16_t transport_checksum_custom (const void *buff, size_t len, size_t ph_len, in_addr_t src_addr,  in_addr_t  dest_addr) {

    const uint16_t *buf=buff;
    uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
    uint32_t sum;

    // Calculate the sum                                            
    sum = 0;
    while (len > 1)
    {
            sum += *buf++;
            if (sum & 0x80000000)
                    sum = (sum & 0xFFFF) + (sum >> 16);
            len -= 2;
    }

    if ( len & 1 )
            // Add the padding if the packet lenght is odd          
            sum += *((uint8_t *)buf);

    // Add the pseudo-header                                        
    sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(prot);
	sum += htons(ph_len);			


    // Add the carries                                              
    while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);

    // Return the one's complement of sum       
    return ( (uint16_t)(~sum)  );
}

static uint16_t transport_checksum6(const void *buff, size_t len, struct in6_addr src_addr, struct in6_addr dest_addr) {
	return transport_checksum_custom6(buff, len, len, src_addr, dest_addr);
}

static uint16_t transport_checksum_custom6(const void *buff, size_t len, size_t ph_len, struct in6_addr src_addr, struct in6_addr dest_addr) {

        const uint16_t *buf=buff;
        uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
        uint32_t sum;

        // Calculate the sum                                            
        sum = 0;
        while (len > 1)
        {
                sum += *buf++;
                if (sum & 0x80000000)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                len -= 2;
        }

        if ( len & 1 )
                // Add the padding if the packet lenght is odd          
                sum += *((uint8_t *)buf);

        // addresses
		for (int i = 0; i <8; i++ ) {
		    sum += *(ip_src+i);	
			sum += *(ip_dst+i);
		}

		sum += htons(prot);			
		sum += htons(ph_len);

        // Add the carries                                              
        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        // Return the one's complement of sum       
        return ( (uint16_t)(~sum)  );
}

void check_checksum (unsigned char * sent, int s_offset, unsigned char * rec, int r_offset, int len, int sentlen, unsigned char* mod, char* mask) {

	int s1, s2, r1, r2; 
	uint16_t ip_checked_len, udp_len, checked_len, ph_len, sent_chksum, rec_chksum, mod_chksum, saved_rec_checksum, mask_chksum;
	char proto[4];

	// ip deduced len
	if (prot3 == 4 )
		ip_checked_len = ntohs (( * (uint16_t *)( & rec[r_offset-20+2]) ) ) - sizeof(struct iphdr);
	else if (prot3 == 6 )
		ip_checked_len = ntohs (( * (uint16_t *)( & rec[r_offset-40+4]) ) );

	if (prot == 6 ) {
		strcpy(proto, "TCP");
		s1 = s_offset + 16;
		checked_len=ip_checked_len;
		ph_len=checked_len;
		sent_chksum =  (( * (uint16_t *)( & sent[r_offset+16]) ) );
		rec_chksum =  (( * (uint16_t *)( & rec[r_offset+16]) ) );
		saved_rec_checksum = rec_chksum;
		mod_chksum =  (( * (uint16_t *)( & mod[r_offset+16]) ) );
		mask_chksum =  (( * (uint16_t *)( & mask[r_offset+16]) ) );
	}
	else if (prot == 17) {
		strcpy(proto, "UDP");
		s1 = s_offset + 6;
		udp_len = ntohs (( * (uint16_t *)( & rec[r_offset+4]) ) );
		if (udpcheck_len_only || udpcheck_4th) 
			checked_len=udp_len;
		else 
			checked_len=ip_checked_len;
		if (udpcheck_len_only || udpcheck_3rd) 
			ph_len=udp_len;
		else 
			ph_len=ip_checked_len;
		sent_chksum =  (( * (uint16_t *)( & sent[r_offset+6]) ) );
		rec_chksum =  (( * (uint16_t *)( & rec[r_offset+6]) ) );
		saved_rec_checksum = rec_chksum;
		mod_chksum =  (( * (uint16_t *)( & mod[r_offset+6]) ) );
		mask_chksum =  (( * (uint16_t *)( & mask[r_offset+6]) ) );
	}

	// check first if checksum itself is correct (will print it later)
	uint16_t correct_rec_checksum;
	if ( prot == 6 )
		(( * (uint16_t *)( & rec[r_offset+16]) ) ) = 0;	
	else if ( prot == 17 )
		(( * (uint16_t *)( & rec[r_offset+6]) ) ) = 0;

	if (prot3 == 4 ) {
		correct_rec_checksum = transport_checksum_custom(&rec[r_offset], checked_len, ph_len, rec_ip->saddr, rec_ip->daddr); 
	}
	else if (prot3 == 6 ) {	
		correct_rec_checksum = transport_checksum_custom6(&rec[r_offset]  , checked_len, ph_len, sent_ip6->saddr, sent_ip6->daddr); 	
	}

	if ( prot == 6 )
		(( * (uint16_t *)( & rec[r_offset+16]) ) ) = saved_rec_checksum;
	else if ( prot == 17 )
		(( * (uint16_t *)( & rec[r_offset+6]) ) ) = saved_rec_checksum;

	// offset between sent, received, and last modified checksum	    
	uint16_t diff = - rec_chksum + sent_chksum;
	if ( rec_chksum > sent_chksum )
		diff + 0xffff;
        uint16_t diff2 = -rec_chksum + mod_chksum;
	if ( rec_chksum > mod_chksum )
		diff2 + 0xffff;

	
	if ( !mask_chksum ) {
		
		if ( diff != 0) {
			printf("%s::Checksum ", proto);
			printf("(%04x->%04x)  ", sent_chksum, rec_chksum);		
			if (prot==6) {
				(( * (uint16_t *)( & mod[r_offset+16]) ) )  = (( * (uint16_t *)( & rec[r_offset+16]) ) );
				(( * (uint16_t *)( & mask[r_offset+16]) ) ) = 1;
			} else if (prot==17) {
				(( * (uint16_t *)( & mod[r_offset+6]) ) )  = (( * (uint16_t *)( & rec[r_offset+6]) ) );
				(( * (uint16_t *)( & mask[r_offset+6]) ) ) = 1;
			}
		}
	} else { 
    	if ( diff2 != 0  ) { // rec_chksum != mod_chksum ) {
			printf("%s::Checksum ", proto);
			printf("(%04x->%04x)  ", mod_chksum, rec_chksum);	
			if (prot==6) {
				(( * (uint16_t *)( & mod[r_offset+16]) ) )  = (( * (uint16_t *)( & rec[r_offset+16]) ) );
			} else if (prot==17) {
				(( * (uint16_t *)( & mod[r_offset+6]) ) )  = (( * (uint16_t *)( & rec[r_offset+6]) ) );
				}
		}			
	}
	   
	// 
	uint16_t chk_diff = correct_rec_checksum - rec_chksum;
	if (correct_rec_checksum < rec_chksum)
		chk_diff += 0xffff;


	// check if checksum can be calculated
	if ( checked_len > len )
		return;

	// info needed even if last seen checksum was wrong
	int last_seen_check;
	if (prot == 6 )
		last_seen_check = tcpcheck_wrg;
	else if (prot == 17 )
		last_seen_check = udpcheck_wrg;	

	if ( ( chk_diff != 0)  || (last_seen_check != 0 ) ){
		if (prot == 6 ) {
			if ( chk_diff != tcpcheck_wrg ) {
				if ( tcpcheck_wrg == 0 )
					printf("!TCP::Checksum (wrg +%04x->+%04x)  ", htons(tcpcheck_wrg ), htons(chk_diff));
				else 
					printf("!TCP::Checksum (wrg +%04x->+%04x)  ", htons(tcpcheck_wrg ), htons(chk_diff));
				tcpcheck_wrg = chk_diff;
			}
			
		}
		else if (prot == 17 )  {
			if ( chk_diff != udpcheck_wrg && rec_chksum!= 0) {
				if ( udpcheck_wrg == 0 )
					printf("!UDP::Checksum (wrg +%04x->+%04x)  ", htons(udpcheck_wrg ), htons(chk_diff));
				else 
					printf("!UDP::Checksum (wrg +%04x->+%04x)  ", htons(udpcheck_wrg ), htons(chk_diff));

				udpcheck_wrg = chk_diff;
			}
		}
	}

}



void set_default_tcp(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) {
    tcp_header = (struct t *)  sent_tcp;

    tcp_header->tcphdr.source = htons(20000); //  ); // RZ it was   htons(48420 + seq); 
    tcp_header->tcphdr.dest = htons(80);// htons(443); // //RZ it was... htons(port)     try port 7 and other values
    tcp_header->tcphdr.seq = 256*48 +1; // RZ it was... rand(); 
    tcp_header->tcphdr.ack_seq = 0; // RZ rand(); // RZ it was ... 0;
    tcp_header->tcphdr.doff = (sizeof(struct tcphdr_mss)) / 4 ; // 6;  //tcp header size    can try 10 ; // RZ it was...

    tcp_header->tcphdr.fin = 0;
    tcp_header->tcphdr.syn = 1; // syn_flag; 
    tcp_header->tcphdr.rst = 0; // it was rst_flag;
    tcp_header->tcphdr.psh = 0;
    tcp_header->tcphdr.ack =0;
    tcp_header->tcphdr.urg = 0;
    
    tcp_header->tcphdr.window = htons(0xffff); 

    tcp_header->tcphdr.check = 0; /* Will calculate the checksum with pseudo-header later */

    tcp_header->tcphdr.urg_ptr = 0;


}

void set_default_udp(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) {

	udp_header = (struct t *)  sent_udp;

	udp_header->source = htons(20000);
	udp_header->dest = htons(80);
	udp_header->len = htons(8); 
	if ( off_udpcheck != 1 ) {
			udp_header->check = 0;
			udp_header->check = transport_checksum(sent_datagram +   sizeof (struct iphdr) , sizeof(struct udphdr) + 0 , inet_addr(local_addr), dst.sin_addr.s_addr); // should be added payload_len, but is 0
		}
}

void set_default_icmp(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) {	
	sent_icmp->type = htons(0); 
	sent_icmp->code = htons(0); 
	sent_icmp->un.gateway = htonl(0); 
	if ( off_icmpcheck != 1 ) {
			sent_icmp->checksum = 0;
			sent_icmp->checksum = ip_checksum(sent_icmp , sizeof(struct my_icmphdr) + payload_len ); // should be added payload_len, but is 0
		}
}

void set_default_ip6(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) {

	struct new_my_ipv6_hdr * sent_ip6 = ((struct new_my_ipv6_hdr *) datagram);
	sent_ip6->version = 6;
		
	set_trafficclass( sent_ip6, 0); 

	if ( prot == 6 ) {
		sent_ip6->payload_len = htons (sizeof (struct tcphdr) ) ;  // not automatically corrected
	} else if ( prot == 17) {
		sent_ip6->payload_len = htons (sizeof (struct udphdr) ) ;  
	}

	set_flowlabel( sent_ip6,0x0); // can it be set?

	sent_ip6->hop_limit = 1; // default
	sent_ip6->nexthdr = prot; // RZ it was... IPPROTO_TCP;

	// source and destination addresses
	inet_pton (AF_INET6, local_addr, &(sent_ip6->saddr));
	inet_pton (AF_INET6, dest_addr, &(sent_ip6->daddr));

	// correct sock_addr struct with source addr
	dst6.sin6_family = AF_INET6;
	memcpy(&dst6.sin6_addr.s6_addr, &sent_ip6->daddr, sizeof(dst6.sin6_addr.s6_addr));
	dst6.sin6_port = 0;

	// update pointers and headers lengths
	sent_tcp = ( (struct tcphdr *) (sent_datagram + sizeof (struct my_ipv6_hdr)   ) );
	sent_udp = ((struct udphdr *) ( sent_datagram +  sizeof (struct my_ipv6_hdr)   ));
	ip_header_len = 40;
}


void set_default_ip(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) {

	// IP
	sent_ip = ((struct iphdr *) datagram) ;
	sent_ip->ihl = 5;
	sent_ip->version = 4;
	sent_ip->tos = 0x00; //0xff; // RZ it was 0
	if ( prot == 6 ) {
		sent_ip->tot_len = ntohs(sizeof (struct iphdr) + sizeof (struct tcphdr_mss) );  // not automatically corrected
	} else if ( prot == 17) {
		sent_ip->tot_len = ntohs(sizeof (struct iphdr) + sizeof (struct udphdr) );  
	} else
		sent_ip->tot_len = ntohs(sizeof (struct iphdr) );  
	sent_ip->id =1; 
	sent_ip->frag_off = 0x00000; 
	sent_ip->ttl = 1; // default
	sent_ip->protocol = prot; 
	sent_ip->check = 0;  //Set to 0 before calculating checksum
	sent_ip->saddr =  inet_addr(local_addr);
	sent_ip->daddr = dst.sin_addr.s_addr; 

}

void reset_chksumwrg() {
	ipcheck_wrg = 0;
	tcpcheck_wrg = 0;
	udpcheck_wrg = 0;
}

void reset_single_tb_params() {

	// overall params
	first_probe = 1;

	// if, addrs and IP version
	new_prot3 = 0;
	new_ifaddrs = 0;
	if_custom_name = 0;
	if_custom_addr = 0;

	delay=0;
	tb_delay=0;

	tcp_header_len = 20;	
	if (prot == 17)
		tcp_header_len = 8;
	if (prot == 1)
		tcp_header_len = 8;
	udp_trailer_len = 0;
	payload_len = 0;
	
	tr_udp_nr = 0;
	tr_ping_nr = 0;

	cst_ttl = 0;
	recv_only = 0;

	//nr 
	serv_to=10;
	nr_tcp_pay = 0;
	nr_syncnt = -1;
	hide_opt_changed=0;
	nr_tracebox_back_ended = 0;
	nr_tcp_ws_reliable = 0;
	nr_tcp_window_reliable = 1;
	nr_tcp_synack_got = 0;
	nr_tcp_no_pay=0;

	// nr_tb
	nr_tb_packet = 0;

	// sr se...
	sr=0;
	se=0;

}

void reset_multi_tb_params() {
	// nr params
	nr = 0;
	nr_prot4 = 6;
	nr_back = 0;
	nr_serv_to=0;
	// nr back
	nr_back_opt = 0;
	nr_ack_opt = 0;
	strcpy(nr_back_options, "");
	strcpy(nr_ack_options, "");

}

void reset_tb_params() {
	reset_single_tb_params();
	reset_multi_tb_params();
}

void reset_ip_params() {

}

void reset_udp_params() {
	off_udpcheck = 0;
	off_udplen = 0;
	udpcheck_add = 0;
	udpcheck_len_only = 0;
}

void reset_tcp_params() {

}


void reset_params() {
	reset_tb_params();

	reset_ip_params();
	
	if ( prot == 6 )
		reset_tcp_params();
	else if ( prot == 17 )
		reset_udp_params();

}

void parse_tr_udp_nr_params( int c, char* v[]) {
	int i = 1;
        while (i < c) {
		int val = 0;
		int def = 0;
		if ( i + 1 < c ) {
			
			if ( strncmp (v[i+1], "-", 1 ) == 0 ) {
				val = 0;
				def = 1;
			} else {
				sscanf(v[i+1], "%x" , &val );
			}

		}
		else  {
			val = 0;
			def = 1;
		}

		if ( strcmp (v[i], "-repeat_tr_udp_nr") == 0 ) {
			repeat_tr_udp_nr = val;
			i = i+2;
		} else if ( strcmp (v[i], "-increase_port_tr_udp_nr") == 0 ) {
			increase_port_tr_udp_nr	 = val + def;
			i = i+1;
		} else
			i++;
	}
}

void parse_tr_ping_nr_params( int c, char* v[]) {
	int i = 1;
        while (i < c) {
		int val = 0;
		int def = 0;
		if ( i + 1 < c ) {
			
			if ( strncmp (v[i+1], "-", 1 ) == 0 ) {
				val = 0;
				def = 1;
			} else {
				sscanf(v[i+1], "%x" , &val );
			}

		}
		else  {
			val = 0;
			def = 1;
		}

		//
		if ( strcmp (v[i], "-repeat_tr_udp_nr") == 0 ) {
			repeat_tr_ping_nr = val;
			i = i+2;
		} else
			i++;
	}
}


void parse_se_params (int c, char * v[]) {
	int i = 1;
        while (i < c) {
		long int val=0;
		int def=0;
		// check if the value is provided
		if ( i + 1 < c ) {			
			parse_custom_value ( v[i+1], &val, &def );
		}
		else  {
			val = 0;
			def = 1;
		}
		// overall
		if ( strcmp (v[i], "-dest") == 0 ) {
				se_dest = val;
				i = i+2; 
		} else if ( strcmp (v[i], "-syncnt") == 0 ) {
				se_syncnt = val;
				i = i+1;
		} else if ( strcmp (v[i], "-ttl") == 0 ) {
				se_ttl = val;
				i = i+1;
		} else if ( strcmp (v[i], "-se_increase_ttl") == 0 ) {
				se_increase_ttl = val;
				se_ttl=1;
				i = i+1;
		} else 
			i++;
	}
}

void parse_nr_params (int c, char * v[]) {
	int i = 1;
        while (i < c) {
		long int val=0;
		int def=0;
		// check if the value is provided
		if ( i + 1 < c ) {			
			parse_custom_value ( v[i+1], &val, &def );
		}
		else  {
			val = 0;
			def = 1;
		}
		// overall
		if ( strcmp (v[i], "-serv") == 0 ) {
				if ( def != 1 )
					if ( prot3 == 4 )
						strcpy (tb_serv_addr, v[i+1]);
				else if ( prot3 == 6 )
					strcpy (tb_serv_addr6, v[i+1]);
				i = i+2;
		} 
		else if ( (strcmp (v[i], "-serv_to") == 0) || (strcmp (v[i], "-sto") == 0) ) {
				nr_serv_to = 1;
				serv_to = val;
				i = i+2;
		}
		else if ( strcmp (v[i], "-client80") == 0 ) {
				if ( def != 1 )
					if ( prot3 == 4 ) {
						strcpy (client80_addr, v[i+1]);
						nr_client80=1;
					}
				i = i+2;
		} 		
		// TCP / UDP
		else if ( (strcmp (v[i], "-source") == 0) || (strcmp (v[i], "-s") == 0) ) {
				nr_source = val;
				i = i+2;
		} else if ( (strcmp (v[i], "-dest") == 0) || (strcmp (v[i], "-d") == 0) ) {
				nr_dest = val;
				i = i+2;
		} else if ( strcmp (v[i], "-nr_syncnt") == 0 ) {
				nr_syncnt = val;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_tcp_pay") == 0 ) {
				nr_tcp_pay = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_tcp_no_pay") == 0 ) {
				nr_tcp_no_pay = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_back") == 0 ) {
				nr_back = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_back_icmp") == 0 ) {
				nr_back = 1;
				nr_back_icmp=1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_print_syn") == 0 ) {
				nr_print_syn = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_print_synack") == 0 ) {
				nr_print_synack = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-no_print_synack") == 0 ) {
				nr_print_synack = 0;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_print_payack") == 0 ) {
				nr_print_payack = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_test_fo") == 0 ) {
				nr_test_fo = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_print_pay_back") == 0 ) {
				nr_print_pay_back = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_back_opt") == 0 ) {
				nr_back_opt = 1;
				if ( def != 1 )
					strcpy (nr_back_options, v[i+1]);
				i = i+1;
		} else if ( strcmp (v[i], "-nr_ack_opt") == 0 ) {
				nr_ack_opt = 1;
				if ( def != 1 )
					strcpy (nr_ack_options, v[i+1]);
				i = i+1;
		} else if ( strcmp (v[i], "-nr_forward_sack") == 0 ) {
				nr_forward_sack = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_tcp_fo") == 0 ) {
				nr_tcp_fo = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_tcp_md5") == 0 ) {
				nr_tcp_md5 = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_tcp_urg") == 0 ) {
				nr_tcp_urg = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_tcp_mss") == 0 ) {
				nr_tcp_mss = val;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_tcp_ws") == 0 ) {
				if ( (val == 0) || (val == 1) || (val == 2) || (val == 6) )
					nr_tcp_ws = val;
				else 
					nr_tcp_ws = 6;
				nr_tcp_ws_got = nr_tcp_ws;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_tcp_rcvbuf") == 0 ) {
				nr_tcp_rcvbuf = val;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_tcp_coalesc") == 0 ) {
				nr_tcp_coalesc = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_frag") == 0 ) {
				nr_frag = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_frag_mf") == 0 ) {
				nr_frag_mf = 1;
				i = i+1;
		} else if ( strcmp (v[i], "-tos") == 0 ) {
				nr_tos = val;
				nr_tc = val;
				i = i+1;
		} else if ( strcmp (v[i], "-ttl") == 0 ) {
				nr_ttl = val;
				nr_hl = val;
				i = i+1;
		} else if ( strcmp (v[i], "-nr_ttl_ex") == 0 ) {
				nr_ttl = nr_extimated_ttl-1 ;
				nr_hl = nr_extimated_ttl -1 ;
				i = i+1;
		} else if ( strcmp (v[i], "-flags_df") == 0 ) {
				nr_df = val;
				i = i+1;
		} else if ( strcmp (v[i], "-tclass") == 0 ) {
				nr_tc = val;
				i = i+1;
		} else if ( strcmp (v[i], "-hop_limit") == 0 ) {
				nr_hl = val;
				i = i+1;
		} else if ( strcmp (v[i], "-dscp") == 0 ) {
				unsigned char v = val*4;
				unsigned char nr_tos_byte = nr_tos;
				nr_tos_byte = v & 0xfc | nr_tos_byte & 0x03;
				unsigned char nr_tc_byte = nr_tc;
				nr_tc_byte = v & 0xfc | nr_tos_byte & 0x03;
				nr_tos = nr_tos_byte;
				nr_tc = nr_tc_byte;
				i = i+1;
		} else if ( strcmp (v[i], "-ecn") == 0 ) {
				unsigned char v = val;
				unsigned char nr_tos_byte = nr_tos;
				nr_tos_byte = v & 0x03 | nr_tos_byte & 0xfc;
				unsigned char nr_tc_byte = nr_tc;
				nr_tc_byte = v & 0x03 | nr_tos_byte & 0xfc;
				nr_tos = nr_tos_byte;
				nr_tc = nr_tc_byte;		
				i = i+1;
		} else if ( strcmp (v[i], "-seq") == 0 ) {
				i = i+2;
		} else if ( strcmp (v[i], "-ack_seq") == 0 ) {
				i = i+2;
		} else if ( strcmp (v[i], "-doff") == 0 ) {
				i = i+2;
		} else if ( strcmp (v[i], "-window") == 0 ) {
				i = i+2;
		} else if ( strcmp (v[i], "-tcpcheck") == 0 ) {
				i = i+2;
		} else if ( strcmp (v[i], "-urg_ptr") == 0 ) {
				i = i+2;
		} else
			i++;
	}
}

void parse_tb_params( int c, char* v[]) {

    // test if args
    int i = 1;
    while (i < c) {
	long int val=0;
	int def=0;
	// check if the value is provided
	if ( i + 1 < c ) {			
		parse_custom_value ( v[i+1], &val, &def );
	}
	else  {
		val = 0;
		def = 1;
	}
	
        // not to mess with internal tb
	if ( strncmp(v[i], "--",2) == 0) {
	return;
	}

	if ( strcmp(v[i], "-/") == 0) {
		strncpy(v[i], "--", 2);
		for ( int j=i+1;j<c;j++)
			if ( strcmp(v[j], "-/") == 0) {
				strncpy(v[j], "--", 2);
			}
		return;
		i++;
        }
		
        if (strcmp(v[i], "-sc") == 0) // script wanted
            { 
            } 
        else if ( strcmp(v[i], "-if") == 0) {
			new_ifaddrs = 1;
			if_custom_name = 1;		
		if ( def != 1 ) {
			strcpy( if_custom_name_string, v[i+1]);
			i += 2;
		} else {
 			strcpy( if_custom_name_string, "localhost");
			i++;
		}		
            } else if ( strcmp(v[i], "-if_addr") == 0) {
			new_ifaddrs = 1;
			if_custom_addr = 1;
		if ( def != 1 ) {
			strcpy( if_custom_addr_string, v[i+1]);
			i += 2;
		} else {
	 		strcpy( if_custom_addr_string, "1");
			i++;
		}
		
            } else if ( strcmp(v[i], "-use_eth_sock") == 0) {
			use_eth_sock=1;
			i++;		
            } else if ( (strcmp(v[i], "-dest_addr") == 0) || (strcmp(v[i], "-i") == 0) ) {
		if ( i + 1 <= c ) {
			strcpy( dest_addr, v[i+1]);
			i += 2;
		} else {
			i++;
		}		
        } else if ( (strcmp(v[i], "-ipv6") == 0) || (strcmp(v[i], "-6") == 0) ) {
            if ( prot3 != 6 )
			new_prot3 = 1;
            prot3 = 6;

			// update pointers and headers lengths
			tcp_header = (struct t *) (sent_datagram +  sizeof (struct my_ipv6_hdr)   );
			udp_header = ((struct udphdr *) ( sent_datagram + sizeof (struct my_ipv6_hdr)  ));
			sent_tcp = ( (struct tcphdr *) (sent_datagram + sizeof (struct my_ipv6_hdr) ) );
			sent_udp = ((struct udphdr *) ( sent_datagram +  sizeof (struct my_ipv6_hdr) ));
			rec_tcp = ( (struct tcphdr *) (recv_pkt + sizeof (struct my_ipv6_hdr) + 8 ) );
			rec_udp = ((struct udphdr *) ( recv_pkt +  sizeof (struct my_ipv6_hdr) + 8 ));
			mod_tcp = (struct t *) (mod_pkt + sizeof (struct my_ipv6_hdr)   );
			mod_udp = ((struct udphdr *) (mod_pkt + sizeof (struct my_ipv6_hdr)  ));
			mask_tcp = (struct t *) (mod_pkt_msk + sizeof (struct my_ipv6_hdr)   );
			mask_udp = ((struct udphdr *) ( mod_pkt_msk + sizeof (struct my_ipv6_hdr)  ));
			custom_tcp = (struct t *) (custom_pkt + sizeof (struct my_ipv6_hdr)   );
			custom_udp = ((struct udphdr *) ( custom_pkt + sizeof (struct my_ipv6_hdr)  ));
			custom_mask_tcp = (struct t *) (custom_pkt_msk + sizeof (struct my_ipv6_hdr)   );
			custom_mask_udp = ((struct udphdr *) ( custom_pkt_msk + sizeof (struct my_ipv6_hdr)  ));
			answer_tcp = ( (struct t *) (answer_pkt ) );
			answer_udp = ((struct udphdr *) ( answer_pkt  ));
			ip_header_len = 40;

            i++;
        } else if ( (strcmp(v[i], "-ipv4") == 0) || (strcmp(v[i], "-4") == 0) ) {
            if ( prot3 != 4 )
			new_prot3 = 1;
			prot3 = 4;
            i++;
        } else if (strcmp(v[i], "-udp") == 0) {
            prot = 17;
			tcp_header_len = 8;
            i++;
        } else if (strcmp(v[i], "-icmp") == 0) {
            prot = 1;
			tcp_header_len = 8;
            i++;
        } else if ( (strcmp(v[i], "-prot4") == 0) || (strcmp(v[i], "-prot") == 0) ) {
            prot = val;				
			tcp_header_len = get_header_len_by_prot4();
            i++;
        } else if ( strcmp(v[i], "-delay") == 0) {
            delay = val;				
            i++;
        } else if ( (strcmp(v[i], "-tb_delay") == 0) ) {
            tb_delay = val;				
            i++;
        } else if ( (strcmp(v[i], "-nr_tb_packet") == 0) ) {
            nr_tb_packet = 1;				
            i++;
        } else if ( (strcmp(v[i], "-nr_tb_hide") == 0) ) {
            nr_tb_hide = 1;				
            i++;
        } else if (strcmp(v[i], "-off_drop_rst") == 0) {
            off_drop_rst = 1;
            i++; 
        } else if (strcmp(v[i], "-off_ipcheck") == 0) {
            off_ipcheck = 1;
            i++; 
        } else if (strcmp(v[i], "-off_tcpcheck") == 0) {
            off_tcpcheck = 1;
            i++;
        } else if (strcmp(v[i], "-off_udpcheck") == 0) {
            off_udpcheck = 1;
            i++;
        } else if (strcmp(v[i], "-off_iplen") == 0) {
            off_iplen = 1;
            i++;
        } else if (strcmp(v[i], "-off_tcplen") == 0) {
            off_tcplen = 1;
            i++;
        } else if (strcmp(v[i], "-off_udplen") == 0) {
            off_udplen = 1;
            i++;
        } else if ( (strcmp(v[i], "-udpcheck_len_only") == 0) || (strcmp(v[i], "-udpcheck_len") == 0) ) {
            udpcheck_len_only = 1;
            i++;
        } else if ( (strcmp(v[i], "-udpcheck_ippay") == 0) || (strcmp(v[i], "-udpcheck_ippaylen") == 0) ) {
            udpcheck_ippay = 1;
            i++;
        } else if (strcmp(v[i], "-udpcheck_3rd") == 0)  {
            udpcheck_3rd = 1;
            i++;
        } else if (strcmp(v[i], "-udpcheck_4th") == 0)  {
            udpcheck_4th = 1;
            i++;
        } else if (strcmp(v[i], "-cst_ttl") == 0) {
            cst_ttl = 1;
            i++;
        } else if (strcmp(v[i], "-off_tcp_pad") == 0) {
            off_tcp_pad = 1;
            i++;
        } else if (strcmp(v[i], "-increase_port") == 0) {
            increase_port = 1;
            i++;
        } else if (strcmp(v[i], "-show_quoted_len") == 0) {
            show_quoted_len = 1;
            i++;
        } else if (strcmp(v[i], "-show_ms") == 0) {
            show_ms = 1;
            i++;
        } else if (strcmp(v[i], "-wayback_ttl") == 0) {
            wayback_ttl = 1;
            i++;
        } else if (strcmp(v[i], "-print_if") == 0) {
            print_if = 1;
            i++;
        } else if (strcmp(v[i], "-print_0") == 0) {
            print_0 = 1;
            i++;
        } else if (strcmp(v[i], "-dont_print_0") == 0) {
            print_0 = 0;
            i++;
        } else if (strcmp(v[i], "-no_icmp_info") == 0) {
            no_icmp_info = 1;
            i++;
        } else if (strcmp(v[i], "-print_last_sent") == 0) {
            print_last_sent = 1;
            i++;
        } else if (strcmp(v[i], "-print_last_recv") == 0) {
            print_last_recv = 1;
            i++;
        } else if ( (strcmp(v[i], "-compare_default")==0) || (strcmp(v[i], "-cd") == 0) ) {
            compare_default = 1;
            i++;
        } else if (strcmp(v[i], "-dest_ip") == 0) {
            dest_ip = 1;
            i++;
        } else if (strcmp(v[i], "-dest_udp") == 0) {
            dest_udp = 1;
            i++;
        } else if (strcmp(v[i], "-dest_tcp") == 0) {
            dest_tcp = 1;
            i++;
        } else if (strcmp(v[i], "-dest_opt") == 0) {
            dest_opt = 1;
            i++;
        } else if (strcmp(v[i], "-dest_ecn") == 0) {
            dest_ecn = 1;
            i++;
        } else if (strcmp(v[i], "-dest_ack") == 0) {
            dest_ack = 1;
            i++;
        } else if (strcmp(v[i], "-dest_pay") == 0) {
            dest_pay = 1;
            i++;
        } else if (strcmp(v[i], "-dest_pay_1") == 0) {
            dest_pay_1 = 1;
            i++;
        } else if (strcmp(v[i], "-dest_pay_printable") == 0) {
            dest_pay_printable = 1;
            i++;
        } else if (strcmp(v[i], "-dest_pay_choice") == 0) {
            dest_pay_choice = 1;
            i++;
        } else if (strcmp(v[i], "-pay_as_text") == 0) {
            pay_as_text = 1;
            i++;
        } else if (strcmp(v[i], "-pay_as_hex") == 0) {
            pay_as_hex = 1;
            i++;
	    } else if (strcmp(v[i], "-show_all_opt") == 0) {
                show_all_opt = 1;
                i++;
            } else if (strcmp(v[i], "-hide_opt_val") == 0) {
                hide_opt_val = 1;
                i++;
	    } else if (strcmp(v[i], "-hide_all_opt_changed") == 0) {
                hide_all_opt_changed = val+def;
                i++;
	    } else if (strcmp(v[i], "-hide_pay") == 0) {
                hide_pay = 1;
                i++;
	    } else if (strcmp(v[i], "-min") == 0) {
				ttl_min = val;
                i=i+2;
	    } else if (strcmp(v[i], "-max") == 0) {
 		ttl_max = val;
                i=i+2;
	    } else if (strcmp(v[i], "-skip_ttl") == 0) {
		skip_ttl = val;
                i=i+2;
	    } else if ( (strcmp(v[i], "-row_stars") == 0) || (strcmp(v[i], "-rs") == 0) ) {
		if ( val!= 0 ) 
			row_stars = val;
                i=i+2;
	    } else if ( (strcmp(v[i], "-max_stars") == 0) || (strcmp(v[i], "-ms") == 0) ){
		if ( val!= 0 ) 
			max_stars = val;
                i=i+2;
	    } else if (strcmp(v[i], "-repeat") == 0) {
		repeat = val;
                i=i+2;
	    } else if ( (strcmp(v[i], "-star_timeout") == 0)  || (strcmp(v[i], "-to") == 0) || (strcmp(v[i], "-st") == 0) ) {
		if ( val < 10 )
			star_timeout = val*1000000;
		else
			star_timeout = val;
                i=i+2;
	    } else if ( (strcmp(v[i], "-recv_only") == 0) || (strcmp(v[i], "-ro") == 0) ){
			recv_only = 1;
            i=i+1;
	    } else if ( (strcmp(v[i], "-nr_keep_port") == 0) || (strcmp(v[i], "-kp") == 0) ){
			nr_keep_port = 1;
            i=i+1;
	    } else if ( strcmp(v[i], "-nr_port") == 0 ){
			nr_custom_port=1;
			nr_port= val;
            i++;
	    } else if ( (strcmp(v[i], "-keep_session") == 0) || (strcmp(v[i], "-ks") == 0) ){
			keep_session = 1;
            i++;
	    } else if ( (strcmp(v[i], "-avoid_retransmission") == 0) || (strcmp(v[i], "-ar") == 0) ){
			avoid_retr = 1;
            i++;
	    } else if (strcmp(v[i], "-dont_increase_seq")==0) {
			dont_increase_seq = 1;
            i++;
	    } else if (strcmp(v[i], "-ack_ad_libitum") == 0) {
			ack_ad_libitum = 1;
            i++;
	    } else if (strcmp(v[i], "-debug_random_mod") == 0) {
			debug_random_mod = 1;
           	i=i+1;
	    } else if (strcmp(v[i], "-mp_checksum") == 0) {
			mp_checksum = val;
            i++;
	    } else if (strcmp(v[i], "-mp_checksum_wrg") == 0) {
		mp_checksum_wrg = 1;
            i++;
	    } else if (strcmp(v[i], "-icmp_du_as_te") == 0) {
		icmp_du_as_te = 1;
            i++;
	    }
	    
	    // NR 
	    else if (strcmp(v[i], "-tr_udp_nr") == 0) {
			tr_udp_nr = 1;
            i++;
	    } else if (strcmp(v[i], "-tr_ping_nr") == 0) {
			tr_ping_nr = 1;
            i++;
	    } else if ( (strcmp(v[i], "-nr") == 0)  || (strcmp(v[i], "-NR") == 0) ){
			nr = 1;
            i++;
	    } else if ( (strcmp(v[i], "-sr") == 0)  || (strcmp(v[i], "-SR") == 0) ){
			nr = 1;
            i++;
	    } else if ( (strcmp(v[i], "-se") == 0)  || (strcmp(v[i], "-SE") == 0) ){
			se = 1;
			nr_print_synack=1;
			nr_print_syn=1;
            i++;
	    } else if ( (strcmp(v[i], "-se_udpo") == 0)  || (strcmp(v[i], "-SE_UDPO") == 0) ){
			se_udpo = 1;
            i++;
	    } else if (strcmp(v[i], "-nr_only") == 0) {
			nr = 1; 
			nr_tb = 0;
	        i=i+1;
	    } else if ( strcmp(v[i], "-nr_tb") == 0 ){
			nr_tb = 1;
            strcpy ( tb_params_string, "\0" );
			for ( int i = 0; i<c; i++ ) {
				if ( !(strcmp (v[i], "-nr_back_opt")) || !(strcmp (v[i], "-nr_ack_opt"))) {
					i++;
					continue;
					}
				if ( (strcmp (v[i], "-nr")) && (strcmp (v[i], "-nr_tb")) && (strcmp (v[i], "-//"))  )
					strcat ( tb_params_string, v[i]	);
				if ( !(strcmp (v[i], "-//") ) )
					strcat ( tb_params_string, "--"	);
				strcat ( tb_params_string, " ");
			}
			i++;
	    } else if (strcmp(v[i], "-print_nr_tb") == 0) {
            print_nr_tb = 1;
            i++;
        } else
        	i++;	
        }
    
}


void parse_ip6_params( int c, char* v[]) {
	int i = 1;
        while (i < c) {
		long int val=0;
		int def=0;
		// check if the value is provided
		if ( i + 1 < c ) {			
			parse_custom_value ( v[i+1], &val, &def );
		}
		else  {
			val = 0;
			def = 1;
		}
		
		// not to mess with internal tb
		if ( strncmp(v[i], "--",2) == 0) {
		return;
		}
		
		// IPv6
		if ( strcmp (v[i], "-hop_limit") == 0 ) {
			custom_mask_ip6->hop_limit = 1;
			custom_ip6->hop_limit = val;
			i = i+2;
			// it means constant ttl
			cst_ttl = 1;	
		} else if ( strcmp (v[i], "-version") == 0 ) {
			custom_mask_ip6->version = 1;
			if ( val == 0 )
				val = prot3;
			custom_ip6->version = val;
			i = i+2;
		} else if ( strcmp (v[i], "-tclass") == 0 ) {
			set_trafficclass( custom_mask_ip6, 1); 
			set_trafficclass( custom_ip6, val); 
			i = i+2;
		} else if ( strcmp (v[i], "-pay_len") == 0 ) {
			custom_mask_ip6->payload_len = 1;
			custom_ip6->payload_len = htons(val);
			off_iplen = 1;
			i = i+2;
		} else if ( strcmp (v[i], "-flow_lbl") == 0 ) {
			set_flowlabel(custom_mask_ip6, 1);
			set_flowlabel(custom_ip6, val);
			i = i+2;
		} else if ( strcmp (v[i], "-nexthdr") == 0 ) {
			custom_mask_ip6->nexthdr = 1;
			custom_ip6->nexthdr = val;
			i = i+2;
		} else if ( strcmp (v[i], "-saddr") == 0 ) {
			if ( def != 1 ) {
				* (uint32_t * ) & (custom_mask_ip6->saddr) = 1;
				inet_pton (AF_INET6, v[i+1], &(custom_ip6->saddr));
				i = i+2;
			}
			else {
				i = i+1;
			}
		} else if ( strcmp (v[i], "-daddr") == 0 ) {
			if ( def != 1 ) {
				* (uint32_t * ) & custom_mask_ip6->daddr = 1;
				inet_pton (AF_INET6, v[i+1], &(custom_ip6->daddr));
				i = i+2;
			}
			else {
				i = i+1;
			}
		} else if ( strcmp (v[i], "-dscp") == 0 ) {
			set_trafficclass_dscp( custom_mask_ip6, 1); 
			set_trafficclass_dscp( custom_ip6, val); 
			i = i+2;
		} else if ( strcmp (v[i], "-ecn") == 0 ) {
			set_trafficclass_ecn( custom_mask_ip6, 1); 
			set_trafficclass_ecn( custom_ip6, val); 
			i = i+2;
		} else 
			i++;
	}
		
}


void parse_ip_params( int c, char* v[]) {
	int i = 1;
        while (i < c) {
		long int val=0;
		int def=0;
		// check if the value is provided
		if ( i + 1 < c ) {			
			parse_custom_value ( v[i+1], &val, &def );
		}
		else  {
			val = 0;
			def = 1;
		}
				
		// not to mess with internal tb
		if ( strncmp(v[i], "--",2) == 0) {
		return;
		}
		
		// IP
		if ( strcmp (v[i], "-ttl") == 0 ) {
			custom_mask_ip->ttl = 1;
			custom_ip->ttl = val;
			i = i+2;
			// it means constant ttl
			cst_ttl = 1;	
		} else if ( strcmp (v[i], "-ihl") == 0 ) {
			custom_mask_ip->ihl = 1;
			custom_ip->ihl = val;
			i = i+2;
		} else if ( strcmp (v[i], "-version") == 0 ) {
			custom_mask_ip->version = 1;
			if ( val == 0 )
				val = prot3;
			custom_ip->version = val;
			i = i+2;
		} else if ( strcmp (v[i], "-tos") == 0 ) {
			custom_mask_ip->tos = 1;
			custom_ip->tos = val;
			i = i+2;
		} else if ( strcmp (v[i], "-tot_len") == 0 ) {
			custom_mask_ip->tot_len = 1;
			custom_ip->tot_len = htons(val);
			off_iplen = 1;
			i = i+2;
		} else if ( strcmp (v[i], "-id") == 0 ) {
			custom_mask_ip->id = 1;
			custom_ip->id = htons(val);
			i = i+2;
		} else if ( strcmp (v[i], "-frag_off_16") == 0 ) {
			custom_mask_ip->frag_off = 1;
			custom_ip->frag_off = htons(val);
			i = i+2;
		} else if ( strcmp (v[i], "-protocol") == 0 ) {
			custom_mask_ip->protocol = 1;
			custom_ip->protocol = val;
			i = i+2;
		} else if ( strcmp (v[i], "-ipcheck") == 0 ) {
			custom_mask_ip->check = 1;
			custom_ip->check = val;
			off_ipcheck = 1;
			i = i+2;
		} else if ( strcmp (v[i], "-saddr") == 0 ) {
			if ( def != 1 ) {
				custom_mask_ip->saddr = 1;
				custom_ip->saddr = val;
				struct in_addr ina;
				htonl(inet_aton(v[i+1], &ina));
				custom_ip->saddr = ina.s_addr;
				i = i+2;
			}
			else {
				i = i+1;
			}
		} else if ( strcmp (v[i], "-daddr") == 0 ) {
			if ( def != 1 ) {
				custom_mask_ip->daddr = 1;
				custom_ip->daddr = val;
				struct in_addr ina;
				htonl(inet_aton(v[i+1], &ina));
				custom_ip->daddr = ina.s_addr;
				i = i+2;
			}
			else {
				i = i+1;
			}
		} else if ( strcmp (v[i], "-flags_res") == 0 ) {
			( ( struct new_iphdr*) custom_mask_ip )->res = 1;
			( ( struct new_iphdr*) custom_ip )->res = val || def;
			i = i+2;			
		} else if ( ( strcmp (v[i], "-flags_df") == 0 ) || ( strcmp (v[i], "-df") == 0 ) ) {
			( ( struct new_iphdr*) custom_mask_ip )->df = 1;
			( ( struct new_iphdr*) custom_ip )->df = val || def;
			i = i+2;
		} else if ( ( strcmp (v[i], "-flags_mf") == 0 ) || ( strcmp (v[i], "-mf") == 0 ) ){
			( ( struct new_iphdr*) custom_mask_ip )->mf = 1;
			( ( struct new_iphdr*) custom_ip )->mf = val || def;
			i = i+2;			
		} else if ( strcmp (v[i], "-frag_off") == 0 ) {
			( ( struct new_iphdr*) custom_mask_ip )->frag_off_5 = 1;
			
			( ( struct new_iphdr*) custom_ip )->frag_off_5 = htons(val) % 0x100;
			( ( struct new_iphdr*) custom_ip )->frag_off_8 = htons(val) / 0x100;

			i = i+2;
		} else if ( strcmp (v[i], "-dscp") == 0 ) {
			( ( struct new_iphdr*) custom_mask_ip )->dscp = 1;
			( ( struct new_iphdr*) custom_ip )->dscp  = val;
			i = i+2;
		} else if ( strcmp (v[i], "-ecn") == 0 ) {
			( ( struct new_iphdr*) custom_mask_ip )->ecn = 1;
			( ( struct new_iphdr*) custom_ip )->ecn = val;
			i = i+2;
		} else {
			i++;	
		}
	}
		
}

void parse_otherprot4_params(c, v) {

}

void parse_icmp_params( int c, char* v[]) {
	int i = 1;
        while (i < c) {
		long int val=0;
		int def=0;
		// check if the value is provided
		if ( i + 1 < c ) {			
			parse_custom_value ( v[i+1], &val, &def );
		}
		else  {
			val = 0;
			def = 1;
		}
		
		// not to mess with internal tb
		if ( strncmp(v[i], "--",2) == 0) {
		return;
		}
		
		// ICMP
		if ( (strcmp (v[i], "-type") == 0) ) {
				custom_mask_icmp->type = 1;
				custom_icmp->type = val;
				i = i+2;
		} else if ( (strcmp (v[i], "-code") == 0) ) {
				custom_mask_icmp->code = 1;
				custom_icmp->code = val;
				i = i+2;
		} else if ( strcmp (v[i], "-icmpcheck") == 0 ) {
				custom_mask_icmp->checksum = 1;
				custom_icmp->checksum = htons(val);
				off_icmpcheck = 1;
				i = i+2;
		} else if ( strcmp (v[i], "-icmp_restofheader") == 0 ) {
				custom_mask_icmp->un.gateway = 1;
				custom_icmp->un.gateway = htonl(val);
				i = i+2;
		} else if ( strcmp (v[i], "-icmp_echo_id") == 0 ) {
				custom_mask_icmp->un.echo.id = 1;
				custom_icmp->un.echo.id = htons(val);
				i = i+2;
		} else if ( strcmp (v[i], "-icmp_echo_seq") == 0 ) {
				custom_mask_icmp->un.echo.sequence = 1;
				custom_icmp->un.echo.sequence = htons(val);
				i = i+2;
		} else if ( strcmp (v[i], "-icmp_frag_unused") == 0 ) {
				custom_mask_icmp->un.frag.__glibc_reserved = 1;
				custom_icmp->un.frag.__glibc_reserved = htons(val);
				i = i+2;
		} else if ( strcmp (v[i], "-icmp_frag_mtu") == 0 ) {
				custom_mask_icmp->un.frag.mtu = 1;
				custom_icmp->un.frag.mtu = htons(val);
				i = i+2;
		} 
		// aggregatd icmp type and code
		  else if ( strcmp (v[i], "-icmp_te") == 0 ) {
				custom_mask_icmp->type = 1;
				custom_icmp->type = 11;
				custom_mask_icmp->code = 1;
				custom_icmp->code = 0;
				i++;
		} else if ( strcmp (v[i], "-icmp_te_frag") == 0 ) {
				custom_mask_icmp->type = 1;
				custom_icmp->type = 11;
				custom_mask_icmp->code = 1;
				custom_icmp->code = 1;
				i++;
		} else if ( strcmp (v[i], "-icmp_echo_req") == 0 ) {
				custom_mask_icmp->type = 1;
				custom_icmp->type = 8;
				custom_mask_icmp->code = 1;
				custom_icmp->code = 0;
				payload_len=56;
				i++;
		} else if ( strcmp (v[i], "-icmp_echo_rep") == 0 ) {
				custom_mask_icmp->type = 1;
				custom_icmp->type = 0;
				custom_mask_icmp->code = 1;
				custom_icmp->code = 0;
				payload_len=56;
				i++;
		} else if ( strcmp (v[i], "-icmp_frag") == 0 ) {
				custom_mask_icmp->type = 1;
				custom_icmp->type = 3;
				custom_mask_icmp->code = 1;
				custom_icmp->code = 4;
				custom_mask_icmp->un.frag.mtu = 1;
				custom_icmp->un.frag.mtu = htons(0x500);
				i++;
		} else if ( strcmp (v[i], "-icmp_port_unr") == 0 ) {
				custom_mask_icmp->type = 1;
				custom_icmp->type = 3;
				custom_mask_icmp->code = 1;
				custom_icmp->code = 3;
				i++;
		} else {
			i++;	
		}
	}

}

void parse_udp_params( int c, char* v[]) {
	int i = 1;
        while (i < c) {
		long int val=0;
		int def=0;
		// check if the value is provided
		if ( i + 1 < c ) {			
			parse_custom_value ( v[i+1], &val, &def );
		}
		else  {
			val = 0;
			def = 1;
		}
		
		// not to mess with internal tb
		if ( strncmp(v[i], "--",2) == 0) {
		return;
		}
		
		// UDP
		if ( (strcmp (v[i], "-source") == 0) || (strcmp (v[i], "-s") == 0) ) {
				custom_mask_udp->source = 1;
				custom_udp->source = htons(val);
				i = i+2;
		} else if ( (strcmp (v[i], "-dest") == 0) || (strcmp (v[i], "-d") == 0)  ) {
				custom_mask_udp->dest = 1;
				custom_udp->dest = htons(val);
				i = i+2;
		} else if ( strcmp (v[i], "-len") == 0 ) {
				custom_mask_udp->len = 1;
				custom_udp->len = htons(val);
				off_udplen = 1;
				i = i+2;
		} else if ( strcmp (v[i], "-udpcheck") == 0 ) {
				custom_mask_udp->check = 1;
				custom_udp->check = htons(val);
				off_udpcheck = 1;
				i = i+2;
		} else {
			i++;	
		}
	}

}

void parse_tcp_params( int c, char* v[]) {
	int i = 1;
        while (i < c) {
		long int val=0;
		int def=0;
		// check if the value is provided
		if ( i + 1 < c ) {			
			parse_custom_value ( v[i+1], &val, &def );
		}
		else  {
			val = 0;
			def = 1;
		}
		
		// not to mess with internal tb
		if ( strncmp(v[i], "--",2) == 0) {
		return;
		}
		
		// TCP
		if ( (strcmp (v[i], "-source") == 0) || (strcmp (v[i], "-s") == 0) ) {
				custom_mask_tcp->tcphdr.source = 1;
				custom_tcp->tcphdr.source = htons(val);
				i = i+2;
		} else if ( ( strcmp (v[i], "-dest") == 0 ) || (strcmp (v[i], "-d") == 0) ) {
				custom_mask_tcp->tcphdr.dest = 1;
				custom_tcp->tcphdr.dest = htons(val);
				dest_port = val;
				i = i+2;
		} else if ( strcmp (v[i], "-seq") == 0 ) {
				custom_mask_tcp->tcphdr.seq = 1;
				custom_tcp->tcphdr.seq = htonl(val);
				i = i+2;
		} else if ( strcmp (v[i], "-ack_seq") == 0 ) {
				custom_mask_tcp->tcphdr.ack_seq = 1;
				custom_tcp->tcphdr.ack_seq = htonl(val);
				i = i+2;
		} else if ( strcmp (v[i], "-ack_seq_add") == 0 ) {
				if (custom_mask_tcp->tcphdr.ack_seq == 1);
					custom_tcp->tcphdr.ack_seq = htonl(ntohl(custom_tcp->tcphdr.ack_seq)+val);
				i = i+2;
		} else if ( strcmp (v[i], "-doff") == 0 ) {
				custom_mask_tcp->tcphdr.doff = 1;
				custom_tcp->tcphdr.doff = val;
				off_tcplen = 1;
				i = i+2;
		} else if ( strcmp (v[i], "-window") == 0 ) {
				custom_mask_tcp->tcphdr.window = 1;
				custom_tcp->tcphdr.window = htons(val);
				i = i+2;
		} else if ( strcmp (v[i], "-tcpcheck") == 0 ) {
				custom_mask_tcp->tcphdr.check = 1;
				custom_tcp->tcphdr.check = htons(val);
				off_tcpcheck = 1;
				i = i+2;
		} else if ( strcmp (v[i], "-urg_ptr") == 0 ) {
				custom_mask_tcp->tcphdr.urg_ptr = 1;
				custom_tcp->tcphdr.urg_ptr = htons(val);

				i = i+2;
		}
		//  TCP flags
		  else if ( strcmp (v[i], "-fin") == 0 ) {
				custom_mask_tcp->tcphdr.fin = 1;
				custom_tcp->tcphdr.fin = val || def;
				i = i+2;
		} else if ( strcmp (v[i], "-syn") == 0 ) {
				custom_mask_tcp->tcphdr.syn = 1;
				custom_tcp->tcphdr.syn = val || def;
				i = i+2;
		} else if ( strcmp (v[i], "-rst") == 0 ) {
				custom_mask_tcp->tcphdr.rst = 1;
				custom_tcp->tcphdr.rst = val || def;
				i = i+2;
		} else if ( strcmp (v[i], "-psh") == 0 ) {
				custom_mask_tcp->tcphdr.psh = 1;
				custom_tcp->tcphdr.psh = val || def;
				i = i+2;
		} else if ( strcmp (v[i], "-ack") == 0 ) {
				custom_mask_tcp->tcphdr.ack = 1;
				custom_tcp->tcphdr.ack = val || def;
				i = i+2;
	
		} else if ( strcmp (v[i], "-urg") == 0 ) {
				custom_mask_tcp->tcphdr.urg = 1;
				custom_tcp->tcphdr.urg = val || def;
				i = i+2;
		// other TCP flags and reserved bits

		} else if ( strcmp (v[i], "-cwr") == 0 ) {
				( ( struct new_tcphdr *) & custom_mask_tcp->tcphdr )-> cwr = 1;
				( ( struct new_tcphdr *)  & custom_tcp->tcphdr )->cwr = val || def;
				i = i+2;
		} else if ( strcmp (v[i], "-ece") == 0 ) {	
				( ( struct new_tcphdr *) & custom_mask_tcp->tcphdr )-> ece = 1;
				( ( struct new_tcphdr *)  & custom_tcp->tcphdr )->ece = val || def;
				i = i+2;
		} else if ( strcmp (v[i], "-ns") == 0 ) {
				( ( struct new_tcphdr *) & custom_mask_tcp->tcphdr )-> ns = 1;
				( ( struct new_tcphdr *)  & custom_tcp->tcphdr )->ns = val || def;
				i = i+2;
		} else if ( strcmp (v[i], "-tcp_res") == 0 ) {
				( ( struct new_tcphdr *) & custom_mask_tcp->tcphdr )-> res = 1;
				if ( def != 1 ) 
					( ( struct new_tcphdr *)  & custom_tcp->tcphdr )->res = val ;					
				else
					( ( struct new_tcphdr *)  & custom_tcp->tcphdr )->res = 1 ;
				i = i+2;
		}

 		else {
			i++;		
		}

	}

}

void parse_tcp_options_params( int c, char* v[]) {
	int i = 1;
        while (i < c) {
		int val = 0;
		int def = 0;
		char * value="\0";
		// check if the value is provided
		if ( i + 1 < c ) {
			if ( ( strncmp (v[i+1], "-" , 1) ) == 0 ) {
				val = 0;
				def = 1;
			}
			else {
				sscanf(v[i+1], "%x" , &val );	
				value = v[i+1];
			}
				
		}
		else {
			val = 0;
			def = 1;
		}
		
		// not to mess with internal tb
		if ( strncmp(v[i], "--",2) == 0) {
		return;
		}
		
		// TCP OPTIONS
		if ( strcmp (v[i], "-tcp_opt_custom") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			int length =  strlen(value) / 2;
			int opt_len=0;
			if ( length >= 2 ) {		
				for (int i=0; i<2; i++) {
					sscanf(value+2*i, "%2x", &val);
					memcpy(a, &val, 1);
					a++;
				}
				
				if (val != 0)
					opt_len = val;
				else
					opt_len = 2;	// correct in case of length set to zero (like in TCP Fast Open)
				for (int i=2; i< opt_len; i++) {
					sscanf(value+2*i, "%2x", &val);
					memcpy(a, &val, 1);
					a++;
				}
				
			}
			tcp_header_len += opt_len;					
			i = i+2;	
		} else if ( strcmp (v[i],"-tcp_opt_mss") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_mss * opt = (struct tcp_option_mss *) a;
			opt->kind = 2;
			opt->len = 4;	
			if ( strcmp ( value, "-default") == 0 )
				opt->mss = htons(0xffff);
			else 
				opt->mss = htons(val);
			tcp_header_len += opt->len;
			i = i+2;	
		}  else if ( strcmp (v[i], "-tcp_opt_sack_perm") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_sack_perm * opt = (struct tcp_option_sack_perm *) a;
			opt->kind = 4;
			opt->len = 2;	
			tcp_header_len += opt->len;
			i = i+2;	
		}  else if ( strcmp (v[i], "-tcp_opt_sack") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_sack * opt = (struct tcp_option_sack *) a;
			opt->kind = 5;
			opt->len = 10;	
			long int val2;
			sscanf(value, "%x" , &val2 );
			if ( strcmp ( value, "-default") == 0 ) {
				memset(a+2, 255, 8); 
			} else {
				a += 2;
				int length =  strlen(value) / 2;
				for (int i=0; i< length; i++) {
				sscanf(value+2*i, "%2x", &val);
				memcpy(a, &val, 1);
				a++;
			}	
			}
			tcp_header_len += opt->len;
			i = i+1;	
		}  else if ( strcmp (v[i], "-tcp_opt_sack_ack") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_sack * opt = (struct tcp_option_sack *) a;
			opt->kind = 5;
			opt->len = 10;	
			opt->start = answer_tcp->tcphdr.seq;
			opt->end = answer_tcp->tcphdr.seq;
			tcp_header_len += opt->len;
			i = i+1;	
		}  else if ( strcmp (v[i], "-tcp_opt_sack_plus_ack") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_sack * opt = (struct tcp_option_sack *) a;
			opt->kind = 5;
			opt->len = 10;	
			int ack_seq = answer_tcp->tcphdr.seq;			
			if ( custom_tcp->tcphdr.ack_seq !=0 ) 
				 ack_seq= custom_tcp->tcphdr.ack_seq;		
			opt->start = ntohl (htonl (ack_seq ) -1 ) ;
			opt->end =  ntohl (htonl (ack_seq ) ) ;
			answer_tcp->tcphdr.seq = ntohl (htonl (ack_seq ) -2 );
			custom_tcp->tcphdr.ack_seq = ntohl (htonl (ack_seq ) -2 );
			tcp_header_len += opt->len;
			i = i+1;	
		} else if ( strcmp (v[i], "-tcp_opt_ws") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_windowscale * opt = (struct tcp_option_windowscale *) a;
			opt->kind = 3;
			opt->len = 3;	
			if ( strcmp ( value, "-default") == 0 )
				opt->value = 0xff;
			else 
				opt->value = val;
			tcp_header_len += opt->len;
			i = i+2;	
		} else if ( strcmp (v[i],"-tcp_opt_mp") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_mpcapable * opt = (struct tcp_option_mpcapable *) a;
			opt->kind = 30;
			opt->len = 8;	
			if ( strcmp ( value, "-default") == 0 )
				opt->subtype = 3;	
			else 
				opt->subtype = val;
			tcp_header_len += opt->len;
			i = i+2;	
		} else if ( strcmp (v[i], "-tcp_opt_ts") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_timestamp * opt = (struct tcp_option_timestamp *) a;
			opt->kind = 8;
			opt->len = 10;	
			if ( strcmp ( value, "-default") == 0 ) {
				opt->tsval =  0xff;
				opt->tsecr = 0;
			} else {
				opt->tsval = val;
				opt->tsecr = 0;
			}
			tcp_header_len += opt->len;
			i = i+2;	
		} else if ( strcmp (v[i], "-tcp_opt_nop") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			for (int i=0; i< val; i++) {
				struct tcp_option_mss * opt = (struct tcp_option_mss *) a;
				opt->kind = 1;
				tcp_header_len++;
				a++;
			}
			i = i+2;	
		} else if ( strcmp (v[i], "-tcp_opt_mp_cap_syn") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_mpcapable * opt = (struct tcp_option_mpcapable *) a;
			opt->kind = 30;
			opt->len = 12;	
			opt->subtype = 0;	
			if (mp_checksum)
				opt->flags = 0x81;	// with checksum
			else
				opt->flags = 0x01;	// without checksum
			opt->key1= 0x10;
			tcp_header_len += opt->len;
			i = i+1;	
		} else if ( strcmp (v[i], "-tcp_opt_mp_cap_ack") == 0 ) {
			if ( mp_cap_syn_ack == 1 ) {
				uint8_t* a = &tcp_header->tcphdr.source;
				a = a + tcp_header_len;
				struct tcp_option_mpcapable * opt = (struct tcp_option_mpcapable *) a;
				opt->kind = 30;
				opt->len = 20;	
				opt->subtype = 0;	
				if (mp_checksum)
					opt->flags = 0x81;	// with checksum
				else
					opt->flags = 0x01;	// without checksum
				opt->key1 = 0x10;
				opt->key2 = mp_cap_syn_ack_key;
				mp_cap_syn_ack = 0;

				tcp_header_len += opt->len;
			}
			else {
				;//fprintf("No MP_Capable SYN ACK received\n", stderr);
			}
			i = i+1;	
		} else if ( strcmp (v[i], "-tcp_opt_mp_join_syn") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_mpjoin * opt = (struct tcp_option_mpcapable *) a;
			opt->kind = 30;
			opt->len = 12;	
			opt->subtype = 0x01;	
			opt->B = 0;
			opt->address_id = 0x02;
			opt->B_token = mptcp_sha1hash(mp_cap_syn_ack_key);
			opt->A_random = 0x10;
			tcp_header_len += opt->len;
			i = i+1;	
		} else if ( strcmp (v[i], "-tcp_opt_mp_dss") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			mptcp_dss_option = a;
			mptcp_dss_option_present = 1;
			struct mptcp_dss_copt * copt = (struct mptcp_dss_copt *) a;
			struct mptcp_dsn_opt * opt = (struct mptcp_dsn_opt *) a;
			copt->mdss_kind = 30;
			copt->mdss_len = 14;
			if (mp_checksum)
				copt->mdss_len=16;
			copt->mdss_subtype = 0x02;	
			copt->mdss_flags = 0x04;
			opt->mdss_dsn=htonl(4216210269);
			opt->mdss_subflow_seqn=htonl(0x01);
			opt->mdss_data_len=htons(72);
//			opt->mdss_dsn=htonl(1);
//			opt->mdss_data_len=htons(0);
//			opt->mdss_subflow_seqn=htonl(0x0);
			tcp_header_len += copt->mdss_len;
			i = i+1;	
		} else if ( strcmp (v[i], "-tcp_opt_mp_dss_ack") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct mptcp_dss_copt * copt = (struct mptcp_dss_copt *) a;
			struct mptcp_dsn_opt * opt = (struct mptcp_dsn_opt *) a;
			copt->mdss_kind = 30;
			copt->mdss_len = 8;	
			copt->mdss_subtype = 0x02;	
			copt->mdss_flags = 0x01;
			opt->mdss_dsn=htonl(0x10);
			//opt->mdss_subflow_seqn=htonl(0x01);;
			//opt->mdss_data_len=htons(106);
			tcp_header_len += copt->mdss_len;
			i = i+1;	
		} else if ( strcmp (v[i], "-tcp_opt_fo_syn1") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_fo * opt = (struct tcp_option_fo *) a;
			opt->kind = 34;
			opt->len = 10;	
			tcp_header_len += opt->len;
			i = i+1;	
		} else if ( strcmp (v[i], "-tcp_opt_fo_syn2") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_fo * opt = (struct tcp_option_fo *) a;
			opt->kind = 34;
			opt->len = fo_cookie_len;
			memcpy ( opt->cookie, fo_cookie, fo_cookie_len);
			tcp_header_len += opt->len;
			i = i+1;	
		} else if ( strcmp (v[i], "-tcp_opt_fo2_syn1") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option * opt = (struct tcp_option_fo *) a;
			opt->kind = 254;
			opt->len = 4;	
			uint8_t magic[2]= {0xf9, 0x89};
			memcpy ( & (opt->value), magic, 2);
			tcp_header_len += opt->len;
			i = i+1;	
		} else if ( strcmp (v[i], "-tcp_opt_fo2_syn2") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option * opt = (struct tcp_option *) a;
			opt->kind = 254;
			opt->len = fo_cookie_len + 2;
			uint8_t magic[2]= {0xf9, 0x89};
			memcpy ( & (opt->value), magic, 2);
			memcpy ( & (opt->value) +2, fo_cookie, fo_cookie_len);
			tcp_header_len += opt->len;
			i = i+1;	
		} else if ( strcmp (v[i], "-tcp_opt_classic") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			unsigned char opts[20] = {0x02, 0x04, 0xff, 0xff, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x0c, 0x7f, 0xd8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06};
			memcpy(a, opts, 20);
			tcp_header_len += 20;
			i = i+1;	
		} else
			i++;
	} // end TCP options
}

void parse_payload_params( int c, char* v[]) {
	int i = 1;
        while (i < c) {
		int val = 0;
		int def = 0;
		char * value;
		// check if the value is provided
		if ( i + 1 < c ) {
			if ( ( strncmp (v[i+1], "-" , 1) ) == 0 ) {
				val = 0;
				def = 1;
			}
			else {
				sscanf(v[i+1], "%x" , &val );	
				value = v[i+1];
			}
				
		}
		else {
			val = 0;
			def = 1;
		}

		
		// not to mess with internal tb
		if ( strncmp(v[i], "--",2) == 0) {
		return;
		}
		
	if ( ( strcmp (v[i], "-payload_custom") == 0 ) || ( strcmp (v[i], "-pay") == 0 ) )  {

		int payload_offset;

		// to be changed!
		if (prot3 == 4 )
			ip_header_len = 20;
		else if (prot3 == 6 )
			ip_header_len = 40;


		// UDP
		if ( prot == 17 ) { 
			payload_offset = ip_header_len + sizeof( struct udphdr) + payload_len;
		}
		// TCP
		else if ( prot == 6 ) {

			// add padding to TCP header if needed			
			if ( off_tcp_pad == 0 ) {
				int padding =  4 - ( tcp_header_len % 4 );
				if ( padding != 4 )
					tcp_header_len += padding;		
			}
			if ( off_tcplen != 1) {
				// set correct lengths		
				tcp_header->tcphdr.doff = tcp_header_len  / 4;
			} 


			payload_offset = ip_header_len + tcp_header_len + payload_len;
		}
		// other prot4 
		else {
			payload_offset = ip_header_len;
		}			
		strcpy(&sent_datagram[payload_offset], value);
		payload_len = payload_len + strlen(value);
		i = i+2;		
	} else if (  ( strcmp (v[i], "-payload_custom_hex") == 0 ) || ( strcmp (v[i], "-payh") == 0 ) ) {
		int payload_offset;
		// TCP
		if ( prot == 6 ) {
			payload_offset= ip_header_len + tcp_header_len +payload_len;
		}
		// UDP
		else if ( prot == 17 ) { 
			payload_offset = ip_header_len	+ sizeof( struct udphdr) +payload_len;
		}
		// ICMP
		else if ( prot == 1 ) { 
			payload_offset = ip_header_len	+ sizeof( struct my_icmphdr) +payload_len;
		}
		// OTHER prot4 
		else {
			payload_offset = ip_header_len ;
		}	
		int length =  strlen(value) / 2;
		uint8_t* a = &sent_datagram[0];
		a = a + payload_offset;
		for (int i=0; i< length; i++) {
			sscanf(value+2*i, "%2x", &val);
			memcpy(a, &val, 1);
			a++;
		}		
		payload_len = payload_len + length;
		i = i+2;
		
		// ICMP pay from last recv pkt
	}  else if ( strcmp (v[i], "-icmp_pay_last_recv") == 0 ) {
				memcpy((char *) sent_icmp+8, answer_pkt, answer_len);
		  		payload_len=answer_len;
				int payload_len_max = 1500 - ip_header_len - ( (prot == 6) ? 20 : 8 ) ;
				if ( payload_len > payload_len_max ) {
					payload_len = payload_len_max;
				}
				i++;
		}
    else if ( strcmp (v[i], "-payload_len") == 0 ) {
		payload_len = val;
		i = i+2;
		}
	else if ( strcmp (v[i], "-payload_len_max") == 0 ) {
		int ipmtu = 1000;
		#if defined(IP_MTU)
			int example_sock = socket( prot3 == 4 ? AF_INET : AF_INET6, SOCK_STREAM, 0);
			int val = 0, ret=-1;
			socklen_t slen=sizeof(val);
			if(prot3==4) {
				ret = getsockopt(example_sock, IPPROTO_IP, IP_MTU, &val, &slen);
			} else if (prot3==6) {
				#if defined(IPPROTO_IPV6) && defined(IPV6_MTU)
						ret = getsockopt(example_sock, IPPROTO_IPV6, IPV6_MTU, &val, &slen);
				#endif
			;
			}
			if (ret==0)
				ipmtu = val;
		#endif
		printf("val IP_MTU %d", val);
		payload_len = ipmtu - ip_header_len - ( (prot == 6) ? 20 : 8 ) ;
		i = i+2;
		}
	else if ( strcmp (v[i], "-payload_len_lte_max") == 0 ) {
		int payload_len_max = 1500 - ip_header_len - ( (prot == 6) ? 20 : 8 ) ;
		if ( payload_len > payload_len_max ) {
			payload_len = payload_len_max;
		}
		i++;
		}
	else 
		i++;
	}
}
	
void parse_post_payload_tcp_params( int c, char* v[]) {
	int i = 1;
        while (i < c) {
		int val = 0;
		int def = 0;
		char * value;
		// check if the value is provided
		if ( i + 1 < c ) {
			if ( ( strncmp (v[i+1], "-" , 1) ) == 0 ) {
				val = 0;
				def = 1;
			}
			else {
				sscanf(v[i+1], "%x" , &val );	
				value = v[i+1];
			}
				
		}
		else {
			val = 0;
			def = 1;
		}

		
		// not to mess with internal tb
		if ( strncmp(v[i], "--",2) == 0) {
		return;
		}
		
		if ( (strcmp (v[i], "-tcp_opt_mp_dss_len_cs") == 0 ) && (mptcp_dss_option_present) ) {
			uint8_t* a = mptcp_dss_option;
			struct mptcp_dss_copt * copt = (struct mptcp_dss_copt *) a;
			struct mptcp_dsn_opt * opt = (struct mptcp_dsn_opt *) a;
			copt->mdss_kind = 30;
			copt->mdss_len = 14;
			if (mp_checksum)
				copt->mdss_len=16;
			copt->mdss_subtype = 0x02;	
			copt->mdss_flags = 0x04;
			opt->mdss_dsn=htonl(4216210269);
			opt->mdss_subflow_seqn=htonl(0x01);
			opt->mdss_data_len=htons(payload_len);
			if (mp_checksum) {
				opt->mdss_xsum =0;
				char * httppay = sent_datagram + sizeof( struct iphdr) + (prot3==6?20:0) + tcp_header_len;
				int len=payload_len;
				uint16_t *buf=httppay;
				uint32_t sum;
				size_t length=len;

				// Calculate the sum                                            //
				sum = 0;
				while (len > 1)
				{
					sum += *buf++;
					if (sum & 0x80000000)
						sum = (sum & 0xFFFF) + (sum >> 16);
					len -= 2;
				}

				if ( len & 1 )
					// Add the padding if the packet lenght is odd          //
					sum += *((uint8_t *)buf);

				// Add pseudo header
				sum+= htons(0x8710) + +htons(0xf99b);
				len=12;
				opt->mdss_xsum;
				buf= & (opt->mdss_dsn);
				while (len >0)
				{
					sum += *buf++;
					if (sum & 0x80000000)
						sum = (sum & 0xFFFF) + (sum >> 16);
					len -= 2;
				}

				// Add the carries                                              //
				while (sum >> 16)
					sum = (sum & 0xFFFF) + (sum >> 16);

				// Return the one's complement of sum       
				opt->mdss_xsum= ( ( (uint16_t)(~sum)  ) );
			}
			if (mp_checksum && mp_checksum_wrg) {
				opt->mdss_xsum =0;
			}
			// tcp_header_len += copt->mdss_len;	// already increased
			i = i+2;	
		} else
			i++;

	}
}

void parse_post_payload_udp_params( int c, char* v[]) {
	int i = 1;
        while (i < c) {
		int val = 0;
		int def = 0;
		char * value;
		// check if the value is provided
		if ( i + 1 < c ) {
			if ( ( strncmp (v[i+1], "-" , 1) ) == 0 ) {
				val = 0;
				def = 1;
			}
			else {
				sscanf(v[i+1], "%x" , &val );	
				value = v[i+1];
			}
				
		}
		else {
			val = 0;
			def = 1;
		}

		
		// not to mess with internal tb
		if ( strncmp(v[i], "--",2) == 0) {
		return;
		}
		
          // UDP Options
	    if ( strcmp (v[i],"-udp_opt_mss") == 0 ) {
			uint8_t* a = &sent_udp->source;
			a += 8 + payload_len + udp_trailer_len;
			struct tcp_option_mss * opt = (struct tcp_option_mss *) a;
			opt->kind = 2;
			opt->len = 4;	
			if ( def )
				opt->mss = htons(0x05c0);
			else 
				opt->mss = htons(val);
			udp_trailer_len += opt->len;
			if (def)
				i++;
			else
				i = i+2;	
		} else if ( (strcmp (v[i], "-udp_opt_custom") == 0 ) || (strcmp (v[i], "-udp_opt") == 0 ) )   {
			uint8_t* a = &sent_udp->source;
			a += 8 + payload_len + udp_trailer_len;
			int length =  strlen(value) / 2;
			for (int i=0; i< length; i++) {
				sscanf(value+2*i, "%2x", &val);
				memcpy(a, &val, 1);
				a++;
				}
			udp_trailer_len += length;
			i = i+2;	
		} else if ( strcmp (v[i],"-udp_opt_cco") == 0 ) {
			// Current UDP Options area	
			int udp_header_payload_len = 8 + payload_len;
			int current_offset = udp_header_payload_len + udp_trailer_len;
			uint8_t* udp_opt_start = (uint8_t*) &(sent_udp->source) + udp_header_payload_len;
			uint8_t* udp_opt_end = (uint8_t*) &(sent_udp->source) + current_offset;
			// add NOP padding if needed
			if (( ( current_offset ) % 2 )==1 ) { // no padding for OCS
				*udp_opt_end = 0x01;	// NOP
				udp_opt_end++;
				udp_trailer_len++;
			}			
			// add CCO
			struct udp_opt_cco * cco = (struct udp_opt_cco *) udp_opt_end;
			cco->kind = 0xCC;
			cco->len = 0x04;		// no len for OCS
			udp_trailer_len += 4; 	// 3 for OCS			
			// Odd byte
			uint8_t odd_byte = 0;
			int odd_byte_offset = 0;
			if ( payload_len % 2 == 1 ) {
				odd_byte =  *(udp_opt_start);
				odd_byte_offset = 1;
			}
			// Initialize CCO value with the length of UDP Options (plus the first odd byte)
			uint16_t cco_initial_value = (uint16_t) udp_trailer_len + (uint16_t) odd_byte;
			cco->value = htons (cco_initial_value);			
			// calculate IP checksum from first even byte of UDP Options to the end of Options (including CCO itself)
			uint8_t * udp_opt_first_even_byte = (uint8_t*) &sent_udp->source + udp_header_payload_len + odd_byte_offset;
			cco->value = ip_checksum( udp_opt_first_even_byte, udp_trailer_len);
			i++;
			// For OCS 
			// if ( payload_len % 2 == 1)
			// 		cco_initial_value = flip_bytes_uint16t (cco_initial_value);
		} else 
			i++;
	}
}



void parse_params( int c, char* v[]) {
	parse_tb_params(c, v);

	// first check for non rooted 
	if ( nr == 1 )
		parse_nr_params(c, v);

	// start ednd
	if ( se == 1 )
		parse_se_params(c, v);

	
	// check fortraceroute only
	if ( tr_udp_nr == 1 ) {
		parse_tr_udp_nr_params(c,v);
		return;
	}

	if ( tr_ping_nr == 1 ) {
		parse_tr_ping_nr_params(c,v);
		return;
	}

	if ( prot3 == 4 )
		parse_ip_params(c, v);
	else if ( prot3 == 6 )
		parse_ip6_params(c, v);

	memset(sent_datagram, 0, 4096);	// to be changed!!!
	if ( prot == 6 ) {
		parse_tcp_params(c, v);
		parse_tcp_options_params(c,v);
	}
	else if (prot == 17 )
		parse_udp_params(c, v);
	else if (prot == 1 )
		parse_icmp_params(c, v);
	else 
		parse_otherprot4_params(c, v);
	parse_payload_params(c, v);
	if ( prot== 6 )
		parse_post_payload_tcp_params(c, v);
	else if ( prot== 17 )
		parse_post_payload_udp_params(c, v);


}





int set_default_fields(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) {

	// set packet

	// set layer 3 header
	if ( prot3 == 4 )
		set_default_ip(sent_datagram, seq, ttl, 1, 0);
	else if (prot3 == 6 )
		set_default_ip6(sent_datagram, seq, ttl, 1, 0);

	// set layer 4 header
	if ( prot == 6 ) {
		set_default_tcp(sent_datagram, seq, ttl, 1, 0);
		//set_default_tcpoptions();
	} else if ( prot == 17) {
		set_default_udp(sent_datagram, seq, ttl, 1, 0);
	} else if ( prot == 1) {
		set_default_icmp(sent_datagram, seq, ttl, 1, 0);
	}
	
}


void set_field ( char* field, char* value) {

	int val;
	sscanf(value, "%x" , &val );
	return;

	// IP
	if ( strcmp (field, "-ttl") == 0 ) {
		sent_ip->ttl = val;
	} else if ( strcmp (field, "-ihl") == 0 ) {
		sent_ip->ihl = val;
	} else if ( strcmp (field, "-version") == 0 ) {
		sent_ip->version = val;
	} else if ( strcmp (field, "-tos") == 0 ) {
		sent_ip->tos = val;
	} else if ( strcmp (field, "-tot_len") == 0 ) {
		sent_ip->tot_len = ntohs(val);
	} else if ( strcmp (field, "-id") == 0 ) {
		sent_ip->id = val;
	} else if ( strcmp (field, "-frag_off") == 0 ) {
		sent_ip->frag_off = ntohs(val);
	} else if ( strcmp (field, "-protocol") == 0 ) {
		sent_ip->protocol = val;
	} else if ( strcmp (field, "-check") == 0 ) {
		sent_ip->check = val;
	} else if ( strcmp (field, "-saddr") == 0 ) {
		sent_ip->saddr = val;
	} else if ( strcmp (field, "-daddr") == 0 ) {
		sent_ip->daddr = val;
	} else if ( strcmp (field, "-flags_res") == 0 ) {
		if (val == 1) sent_ip->frag_off += 0x80;
	} else if ( strcmp (field, "-flags_df") == 0 ) {
		if (val == 1) sent_ip->frag_off += 0x40;
	} else if ( strcmp (field, "-flags_mf") == 0 ) {
		if (val == 1) sent_ip->frag_off += 0x20;
	} else if ( strcmp (field, "-dscp") == 0 ) {
		sent_ip->tos = val - (val%4);
	} else if ( strcmp (field, "-ecn") == 0 ) {
		sent_ip->tos -= (sent_ip->tos % 4);
		sent_ip->tos += (val%4);
	} else {
		;	
	}
	
	
	// UDP
	if ( prot == 17 ) {
		if ( strcmp (field, "-source") == 0 ) {
			udp_header->source = htons(val);
		} else if ( strcmp (field, "-dest") == 0 ) {
			udp_header->dest = htons(val);
		} else if ( strcmp (field, "-len") == 0 ) {
			udp_header->len = htons(val);
		} else if ( strcmp (field, "-udpcheck") == 0 ) {
			udp_header->check = htons(val);
		}
	}

	// TCP
	else if ( prot == 6 ) {
		if ( strcmp (field, "-source") == 0 ) {
			tcp_header->tcphdr.source = htons(val);
		} else if ( strcmp (field, "-dest") == 0 ) {
			tcp_header->tcphdr.dest = htons(val);
		} else if ( strcmp (field,"-seq") == 0 ) {
			tcp_header->tcphdr.seq = htonl(val);
		} else if ( strcmp (field, "-ack_seq") == 0 ) {
			tcp_header->tcphdr.ack_seq = htonl(val);
		} else if ( strcmp (field, "-doff") == 0 ) {
			tcp_header->tcphdr.doff = val;
		} else if ( strcmp (field, "-window") == 0 ) {
			tcp_header->tcphdr.window = htons(val);
		} else if ( strcmp (field, "-tcpcheck") == 0 ) {
			tcp_header->tcphdr.check = htons(val);
		} else if ( strcmp (field, "-urg_ptr") == 0 ) {
			tcp_header->tcphdr.urg_ptr = htons(val);
		}
		// TCP flags
		  else if ( strcmp (field, "-fin") == 0 ) {
			if ( val == 0 )
				tcp_header->tcphdr.fin =  0;
			else
				tcp_header->tcphdr.fin =  1;	
		} else if ( strcmp (field, "-syn") == 0 ) {
			if ( val == 0 )
				tcp_header->tcphdr.syn =  0;
			else
				tcp_header->tcphdr.syn =  1;	
		} else if ( strcmp (field, "-rst") == 0 ) {
			if ( val == 0 )
				tcp_header->tcphdr.rst =  0;
			else
				tcp_header->tcphdr.rst =  1;	
		} else if ( strcmp (field, "-psh") == 0 ) {
			if ( val == 0 )
				tcp_header->tcphdr.psh =  0;
			else
				tcp_header->tcphdr.psh =  1;	
		} else if ( strcmp (field, "-ack") == 0 ) {

			for (int i = 0; i<4; i++)
				sent_datagram[28+i] = saved_seq [i];
			sent_datagram[31] = sent_datagram[31] +1;
//			tcp_header->tcphdr.seq = htonl (ntohl(tcp_header->tcphdr.seq) +1 );
			//tcp_header->tcphdr.ack_seq++;

			if ( val == 0 )
				tcp_header->tcphdr.ack =  0;
			else
				tcp_header->tcphdr.ack =  1;	
		} else if ( strcmp (field, "-urg") == 0 ) {
			if ( val == 0 )
				tcp_header->tcphdr.urg =  0;
			else
				tcp_header->tcphdr.urg =  1;	
		} 
		// TCP other flags and reserved bits
		else if ( strcmp (field, "-cwr") == 0 ) {
			if ( val == 1 ) {
				uint8_t* a = &tcp_header->tcphdr.ack_seq;
				a=a+5;	
				*a += 128;
			}
		} else if ( strcmp (field, "-ece") == 0 ) {
			if ( val == 1 ) {
				uint8_t* a = &tcp_header->tcphdr.ack_seq;
				a=a+5;	
				*a += 64;		
			}	
		} else if ( strcmp (field, "-ns") == 0 ) {
			if ( val == 1 ) {
				uint8_t* a = &tcp_header->tcphdr.ack_seq;
				a=a+4;	
				*a += 1;		
			}
		}  else if ( strcmp (field, "-res") == 0 ) {
			if ( val == 1 ) {			
				uint8_t* a = &tcp_header->tcphdr.ack_seq;
				a=a+4;	
				*a += 14;
			}
		} 
		// TCP OPTIONS
		else if ( strcmp (field, "-tcp_opt_custom") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			int length =  strlen(value) / 2;
			int opt_len=0;
			/*			
			for (int i=0; i< length; i++) {
				sscanf(value+2*i, "%2x", &val);
				memcpy(a, &val, 1);
				a++;
			}
			*/
			if ( length >= 2 ) {		
				for (int i=0; i<2; i++) {
					sscanf(value+2*i, "%2x", &val);
					memcpy(a, &val, 1);
					a++;
				}
				opt_len = val;
				for (int i=2; i< opt_len; i++) {
					sscanf(value+2*i, "%2x", &val);
					memcpy(a, &val, 1);
					a++;
				}
				
			}
			tcp_header_len += opt_len;					
		} else if ( strcmp (field, "-tcp_opt_mss") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_mss * opt = (struct tcp_option_mss *) a;
			opt->kind = 2;
			opt->len = 4;	
			if ( strcmp ( value, "-default") == 0 )
				opt->mss = htons(0xffff);
			else 
				opt->mss = htons(val);
			tcp_header_len += opt->len;
			//

		}  else if ( strcmp (field, "-tcp_opt_sack_perm") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_sack_perm * opt = (struct tcp_option_sack_perm *) a;
			opt->kind = 4;
			opt->len = 2;	
			tcp_header_len += opt->len;
		}  else if ( strcmp (field, "-tcp_opt_sack") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_sack * opt = (struct tcp_option_sack *) a;
			opt->kind = 5;
			opt->len = 10;	
			long int val2;
			sscanf(value, "%x" , &val2 );
			if ( strcmp ( value, "-default") == 0 ) {
				memset(a+2, 255, 8); 
			} else {
				a += 2;
				int length =  strlen(value) / 2;
				for (int i=0; i< length; i++) {
				sscanf(value+2*i, "%2x", &val);
				memcpy(a, &val, 1);
				a++;
			}	
			}
			tcp_header_len += opt->len;
		} else if ( strcmp (field, "-tcp_opt_ws") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_windowscale * opt = (struct tcp_option_windowscale *) a;
			opt->kind = 3;
			opt->len = 3;	
			if ( strcmp ( value, "-default") == 0 )
				opt->value = 0xff;
			else 
				opt->value = val;
			tcp_header_len += opt->len;
		} else if ( strcmp (field, "-tcp_opt_mp") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_mpcapable * opt = (struct tcp_option_mpcapable *) a;
			opt->kind = 30;
			opt->len = 8;	
			if ( strcmp ( value, "-default") == 0 )
				opt->subtype = 3;	
			else 
				opt->subtype = val;
			tcp_header_len += opt->len;
		} else if ( strcmp (field, "-tcp_opt_ts") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			struct tcp_option_timestamp * opt = (struct tcp_option_timestamp *) a;
			opt->kind = 8;
			opt->len = 10;	
			if ( strcmp ( value, "-default") == 0 ) {
				opt->tsval =  0xff;
				opt->tsecr = 0;
			} else {
				opt->tsval = val;
				opt->tsecr = 0;
			}
			tcp_header_len += opt->len;
		} else if ( strcmp (field, "-tcp_opt_nop") == 0 ) {
			uint8_t* a = &tcp_header->tcphdr.source;
			a = a + tcp_header_len;
			for (int i=0; i< val; i++) {
				struct tcp_option_mss * opt = (struct tcp_option_mss *) a;
				opt->kind = 1;
				tcp_header_len++;
				a++;
			}
		}
	} // end UDP TCP(including options)


	// PAYLOAD
	if ( strcmp (field, "-payload_custom") == 0 ) {

		int payload_offset;
		// UDP
		if ( prot == 17 ) { 
			payload_offset = sizeof( struct iphdr)	+ sizeof( struct udphdr);
		}
		// TCP
		else if ( prot == 6 ) {

			// add padding to TCP header if needed			
			if ( off_tcp_pad == 0 ) {
				int padding =  4 - ( tcp_header_len % 4 );
				if ( padding != 4 )
					tcp_header_len += padding;		
			}
			if ( off_tcplen != 1) {
				// set correct lengths		
				tcp_header->tcphdr.doff = tcp_header_len  / 4;
			} 


			payload_offset = sizeof( struct iphdr) + tcp_header_len + payload_len;
		}
		strcpy(&sent_datagram[payload_offset], value);
		payload_len = strlen(value) + payload_len;

	} else if ( strcmp (field, "-payload_custom_hex") == 0 ) {
		int payload_offset;
		// UDP
		if ( prot == 17 ) { 
			payload_offset = sizeof( struct iphdr)	+ sizeof( struct udphdr);
		}
		// TCP
		else if ( prot == 6 ) {
			payload_offset = sizeof( struct iphdr) + tcp_header_len;
		}
		int length =  strlen(value) / 2;
		uint8_t* a = &sent_datagram[0];
		a = a + payload_offset;
		for (int i=0; i< length; i++) {
			sscanf(value+2*i, "%2x", &val);
			memcpy(a, &val, 1);
			a++;
		}		
		payload_len += length;
		//printf("pay %d %s", payload_len, &sent_datagram[payload_offset]);
	}  else if ( strcmp (field, "-payload_len") == 0 ) {
		payload_len = val;
		}
	
}


int set_custom_fields (char datagram[], int seq, int ttl, int syn_flag, int rst_flag) {
    // test if custom fields
    if (custom_fields_count > 2)  {
        int i = 2;
        while (i < custom_fields_count ) {
            set_field(custom_fields[i], custom_fields[i+1]);
	    i = i+2;
        }
    }


		// IP
	if ( prot3 == 4 ) {
		if ( custom_mask_ip->ttl  == 1 ) {
			sent_ip->ttl = custom_ip->ttl;
		}


		if ( custom_mask_ip->ihl  == 1 ) {
			sent_ip->ihl = custom_ip->ihl;
		}

		if ( custom_mask_ip->version  == 1 ) {
			sent_ip->version = custom_ip->version;
		}

		if ( custom_mask_ip->tos  == 1 ) {
			sent_ip->tos = custom_ip->tos;
		}

		if ( custom_mask_ip->tot_len  == 1 ) {
			sent_ip->tot_len = custom_ip->tot_len;
		}

		if ( custom_mask_ip->id  == 1 ) {

			sent_ip->id = custom_ip->id;
		}

		if ( custom_mask_ip->frag_off  == 1 ) {
			sent_ip->frag_off = custom_ip->frag_off;
		}

		if ( custom_mask_ip->protocol  == 1 ) {
			sent_ip->protocol = custom_ip->protocol;
		}

		if ( custom_mask_ip->check  == 1 ) {
			sent_ip->check = custom_ip->check;
		}

		if ( custom_mask_ip->saddr  == 1 ) {
			sent_ip->saddr = custom_ip->saddr;
		}

		if ( custom_mask_ip->daddr  == 1 ) {
			sent_ip->daddr = custom_ip->daddr;
		}

		if ( ( ( struct new_iphdr*) custom_mask_ip )->res  == 1 ) {
			( ( struct new_iphdr*)  sent_ip )->res = ( ( struct new_iphdr*) custom_ip )->res ;
			/*			
			struct byte_by_bits* B = ( struct byte_by_bits* ) & sent_ip->frag_off;
			#  if __BYTE_ORDER == __LITTLE_ENDIAN			
				B->bit7 =  v_flags_res;
			#  elif __BYTE_ORDER == __BIG_ENDIAN
				B->bit0 =  v_flags_res;
			# endif
			*/

		}
		
		if ( ( ( struct new_iphdr*) custom_mask_ip )->df  == 1 ) {
			( ( struct new_iphdr*) sent_ip )->df = ( ( struct new_iphdr*) custom_ip )->df ;

		}

		if ( ( ( struct new_iphdr*) custom_mask_ip )->mf  == 1 ) {
			( ( struct new_iphdr*) sent_ip )->mf = ( ( struct new_iphdr*) custom_ip )->mf ;
		}

		if ( ( ( struct new_iphdr*) custom_mask_ip )->frag_off_5 == 1 ) {
			( ( struct new_iphdr*) sent_ip )->frag_off_5 = ( ( struct new_iphdr*) custom_ip )->frag_off_5;
			( ( struct new_iphdr*) sent_ip )->frag_off_8 = ( ( struct new_iphdr*) custom_ip )->frag_off_8;

		}


		if ( ( ( struct new_iphdr*) custom_mask_ip )->dscp  == 1 ) {
			( ( struct new_iphdr*) sent_ip )->dscp = ( ( struct new_iphdr*) custom_ip )->dscp ;
		}

		if ( ( ( struct new_iphdr*) custom_mask_ip )->ecn  == 1 ) {
			( ( struct new_iphdr*) sent_ip )->ecn = ( ( struct new_iphdr*) custom_ip )->ecn ;
		}

	}
	
	// IPv6
	if ( prot3 == 6 ) {
		if ( custom_mask_ip6->hop_limit  == 1 ) {
			sent_ip6->hop_limit = sent_ip6->hop_limit;
		}

		if ( custom_mask_ip6->version  == 1 ) {
			sent_ip6->version = sent_ip6->version;
		}
		if ( get_trafficclass(custom_mask_ip6)  == 1 ) {
			set_trafficclass(sent_ip6, get_trafficclass(custom_ip6));
		}

		if ( custom_mask_ip6->payload_len  == 1 ) {
			sent_ip6->payload_len = sent_ip6->payload_len;
		}

		if ( get_flowlabel(custom_mask_ip6)  == 1 ) {
			set_flowlabel(sent_ip6, get_flowlabel(custom_ip6));
		}

		if ( custom_mask_ip6->nexthdr == 1 ) {
			sent_ip6->nexthdr = sent_ip6->nexthdr;
		}

		if (* (uint32_t * ) & (custom_mask_ip6->saddr) == 1 ) {
			copy_in6_addr(& (sent_ip6->saddr), & (custom_ip6->saddr));
		}

		if (* (uint32_t * ) & (custom_mask_ip6->daddr) == 1 ) {
			copy_in6_addr(& (sent_ip6->daddr), & (custom_ip6->daddr));
		}
		// dscp and ecn separated
		if ( get_trafficclass_dscp(custom_mask_ip6)  == 1 ) {
			set_trafficclass_dscp(sent_ip6, get_trafficclass_dscp(custom_ip6));
		}
		if ( get_trafficclass_ecn(custom_mask_ip6)  == 1 ) {
			set_trafficclass_ecn(sent_ip6, get_trafficclass_ecn(custom_ip6));
		}

	}

	// ICMP
	if ( prot == 1 ) {

		if ( custom_mask_icmp->type  == 1 ) {
			sent_icmp->type = custom_icmp->type;
		}
		if ( custom_mask_icmp->code  == 1 ) {
			sent_icmp->code = custom_icmp->code;
		}
		if ( custom_mask_icmp->checksum  == 1 ) {
			sent_icmp->checksum = custom_icmp->checksum;
		}

		if ( ( (sent_icmp->type == 8) || (sent_icmp->type == 0) ) && (sent_icmp->code == 0) ) {
			if ( custom_mask_icmp->un.echo.id  == 1 ) {
				sent_icmp->un.echo.id = custom_icmp->un.echo.id;
			}
			if ( custom_mask_icmp->un.echo.sequence  == 1 ) {
				sent_icmp->un.echo.sequence = custom_icmp->un.echo.sequence;
			}
		}
		else if ( (sent_icmp->type == 3) && (sent_icmp->code == 4) ) {
			if ( custom_mask_icmp->un.frag.__glibc_reserved  == 1 ) {
				sent_icmp->un.frag.__glibc_reserved = custom_icmp->un.frag.__glibc_reserved;
			}
			if ( custom_mask_icmp->un.frag.mtu  == 1 ) {
				sent_icmp->un.frag.mtu = custom_icmp->un.frag.mtu;
			}
		}
		else {
			if ( custom_mask_icmp->un.gateway  == 1 ) {
				sent_icmp->un.gateway = custom_icmp->un.gateway;
			}
		}

	}

	// UDP
	if ( prot == 17 ) {

		if ( custom_mask_udp->source  == 1 ) {
			udp_header->source = custom_udp->source;
		}

		if ( custom_mask_udp->dest  == 1 ) {
			udp_header->dest = custom_udp->dest;
		}

		if ( custom_mask_udp->len  == 1 ) {
			udp_header->len = custom_udp->len;
		}

		if ( custom_mask_udp->check  == 1 ) {

			udp_header->check = custom_udp->check;
		}

	}

	// TCP
	if ( prot == 6 ) {

		if ( custom_mask_tcp->tcphdr.source  == 1 ) {
			tcp_header->tcphdr.source = custom_tcp->tcphdr.source;
		}

		if ( custom_mask_tcp->tcphdr.dest  == 1 ) {
			tcp_header->tcphdr.dest = custom_tcp->tcphdr.dest;
		}

		if ( custom_mask_tcp->tcphdr.seq  == 1 ) {
			tcp_header->tcphdr.seq = custom_tcp->tcphdr.seq;
		}

		if ( custom_mask_tcp->tcphdr.ack_seq  == 1 ) {
			tcp_header->tcphdr.ack_seq = custom_tcp->tcphdr.ack_seq;
		}

		if ( custom_mask_tcp->tcphdr.doff  == 1 ) {
			tcp_header->tcphdr.doff = custom_tcp->tcphdr.doff;
		}

		if ( custom_mask_tcp->tcphdr.window  == 1 ) {
			tcp_header->tcphdr.window = custom_tcp->tcphdr.window;
		}

		if ( custom_mask_tcp->tcphdr.check  == 1 ) {
			tcp_header->tcphdr.check = custom_tcp->tcphdr.check;
		}

		if ( custom_mask_tcp->tcphdr.urg_ptr  == 1 ) {
			tcp_header->tcphdr.urg_ptr = custom_tcp->tcphdr.urg_ptr;
		}
		
		// TCP flags
		if ( custom_mask_tcp->tcphdr.fin  == 1 ) {
			tcp_header->tcphdr.fin = custom_tcp->tcphdr.fin;
		}

		if ( custom_mask_tcp->tcphdr.syn  == 1 ) {
			tcp_header->tcphdr.syn = custom_tcp->tcphdr.syn;
		}

		if ( custom_mask_tcp->tcphdr.rst  == 1 ) {
			tcp_header->tcphdr.rst = custom_tcp->tcphdr.rst;
		}

		if ( custom_mask_tcp->tcphdr.psh  == 1 ) {
			tcp_header->tcphdr.psh = custom_tcp->tcphdr.psh;
		}

		if ( custom_mask_tcp->tcphdr.ack  == 1 ) {
			tcp_header->tcphdr.ack = custom_tcp->tcphdr.ack;

				// keep tcp session old version
/*		
				for (int i = 0; i<4; i++)
					sent_datagram[28+i] = saved_seq [i];
				sent_datagram[31] = sent_datagram[31] +1;
*/				
				// real keep session
			if ( (custom_mask_tcp->tcphdr.seq  == 0) )
				//commented only for SACK stimulation		
				// tcp_header->tcphdr.seq = answer_tcp->tcphdr.ack_seq; //htonl (ntohl(tcp_header->tcphdr.seq) +1 );
				// maybe better payload_sent_till now + 1
					if (!dont_increase_seq)
						tcp_header->tcphdr.seq = htonl (ntohl(*((uint64_t*)saved_ack_seq)));

				
			if ( custom_mask_tcp->tcphdr.ack_seq  == 0)
//				if ( ( answer_tcp->tcphdr.syn == 1) && (answer_tcp->tcphdr.ack == 1 ) )
				if ( saved_flags==0x12 )
					//tcp_header->tcphdr.ack_seq = htonl (ntohl(answer_tcp->tcphdr.seq) +1 );
					tcp_header->tcphdr.ack_seq = htonl (ntohl(*((uint64_t*)saved_seq)) +1 );
				else
					//tcp_header->tcphdr.ack_seq = htonl (ntohl(answer_tcp->tcphdr.seq));
					tcp_header->tcphdr.ack_seq = htonl (ntohl(*((uint64_t*)saved_seq)));

			// add line to keep count of received bytes
		}

		if ( custom_mask_tcp->tcphdr.urg  == 1 ) {
			tcp_header->tcphdr.urg = custom_tcp->tcphdr.urg;
		}

		// disable res1 and res2 field
		if ( custom_mask_tcp->tcphdr.res1  == 1 ) {
			;//tcp_header->tcphdr.res1 = custom_tcp->tcphdr.res1;
		}
		if ( ( ( struct new_tcphdr *) & custom_mask_tcp->tcphdr ) -> cwr == 1 ) {
			( ( struct new_tcphdr *) & tcp_header->tcphdr ) -> cwr = ( ( struct new_tcphdr *) & custom_tcp->tcphdr ) -> cwr;
		}

		if ( ( ( struct new_tcphdr *) & custom_mask_tcp->tcphdr ) -> ece == 1 ) {
			( ( struct new_tcphdr *) & tcp_header->tcphdr ) -> ece = ( ( struct new_tcphdr *) & custom_tcp->tcphdr ) -> ece;
		}

		if ( ( ( struct new_tcphdr *) & custom_mask_tcp->tcphdr ) -> ns == 1 ) {
			( ( struct new_tcphdr *) & tcp_header->tcphdr ) -> ns = ( ( struct new_tcphdr *) & custom_tcp->tcphdr ) -> ns;
		}

		if ( ( ( struct new_tcphdr *) & custom_mask_tcp->tcphdr ) -> res == 1 ) {
			( ( struct new_tcphdr *) & tcp_header->tcphdr ) -> res = ( ( struct new_tcphdr *) & custom_tcp->tcphdr ) -> res;
		}

	}

		// TCP Options and payload

	
	
}

static int  send_probe(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) {	
// print_pkt(sent_datagram, 80);	
// print_pkt(&dst, sizeof(struct sockaddr));
	int sent;	
		
	int len = ip_header_len + tcp_header_len + payload_len + udp_trailer_len;
	
	if ( use_eth_sock ) {
	// need to reset destination address
		dst.sin_addr.s_addr = inet_addr(dest_addr);
		dst.sin_family = AF_INET;
		dst.sin_port = htons( 80 );
	}
	
	// sending packet 
	if ( prot3 == 4 )
		sent = sendto(sndsock, sent_datagram, len, 0,  (const struct sockaddr *) &dst /* &dest_lsa->u.sa*/, sizeof(struct sockaddr) /*dest_lsa->len*/ );
	else if ( prot3 == 6 ) {
		sent = sendto(sndsock6, sent_datagram, len, 0, (struct sockaddr *) &dst6, sizeof(dst6));
	}
	// times
	gettimeofday(&t1, NULL);

	
	if (sent <= 0)
		printf("*  [Error (Packet not sent)]", sent);

	return sent;

}


int wait_for_reply_tcp(int sck, len_and_sockaddr *from_lsa, struct sockaddr *to, unsigned *timestamp_us, int *left_ms) {

	static int count = 0;
	int read_len;	
	int i;
	int usecs;

	for ( i = 0; i < 1; i++ ) {

		read_len = recvfrom(sndsock, answer_pkt, 4096, MSG_DONTWAIT,  (const  struct sockaddr *) &dst2, &dst2len); 
		if ( read_len != -1 )  
			// check source IP and port
			if ( ( answer_ip->saddr != sent_ip->daddr  ) 
			  || ( answer_ip->daddr != sent_ip->saddr  ) 
			  || ( answer_tcp->tcphdr.source != tcp_header->tcphdr.dest ) 
			  || ( answer_tcp->tcphdr.dest != tcp_header->tcphdr.source ) ) {
					read_len  == -1 ;
					continue;
				}
		else {
			gettimeofday( &t2, NULL);
		
			// show cycles (to be cut)
			// printf("[cycle %d] ", i);  

	 		return read_len;	

		}
		// usleep(star_timeout / 1000);
	}
	return -1;

}

static int wait_for_reply(int sck, len_and_sockaddr *from_lsa, struct sockaddr *to, unsigned *timestamp_us, int *left_ms, int*  which_sock) {

	static int count = 0;
	int read_len;	
	int i;
	int usecs;

	// new part with select()

	int activity = 0;
	struct timeval timeout, time1, time2;
	timeout.tv_sec	= star_timeout / 1000000;
	timeout.tv_usec	= star_timeout % 1000000;

	// keep time in mind to continue after unwanted receive
	gettimeofday(&time1, NULL);
	while (activity >= 0 ) {
	
		// fd_s et
		FD_ZERO(&readfds);
		if (prot3 == 4 ) {
			FD_SET(sndsock, &readfds);
			FD_SET(rcvsock, &readfds);	
			if (sndsock >= rcvsock )
				max_sd = sndsock;
			else
				max_sd = rcvsock;

		}
		else if (prot3 == 6 ) {
			FD_SET(sndsock6b, &readfds);
			FD_SET(rcvsock6, &readfds);
			if (sndsock6b >= rcvsock6 )
				max_sd = sndsock6b;
			else
				max_sd = rcvsock6;
			
		}

   		activity = select( max_sd + 1 , &readfds , NULL , NULL , &timeout);


		// keep in mind remaining time
		gettimeofday(&time2, NULL);
		
		// record RTT in case it's a real receive
		gettimeofday(&t2, NULL);

		long int diff = star_timeout - ( (time2.tv_usec + 1000000 * time2.tv_sec) - (time1.tv_usec + 1000000 * time1.tv_sec) );  
		timeout.tv_sec	= diff / 1000000;
		timeout.tv_usec	= diff % 1000000;

		//printf ("diff %d\n", diff);
		if ( activity < 0 )
			return -1;
		
		if ( prot3 == 4 ) {
			if ( FD_ISSET(rcvsock, &readfds) ) { //continue;
				read_len = recvfrom(rcvsock, recv_pkt, 4096, MSG_DONTWAIT,  (struct sockaddr *) &dst2, &dst2len); 			
				*which_sock = 1;	
				// skip if we are not waiting for ICMP
				if ( recv_only == 1 )
					continue;	
				// if using eth sock check if it is correct IPv and ICMP
				if ( use_eth_sock ) {
					for (int i=0;i<4096-14;i++)
						recv_pkt[i]=recv_pkt[i+14];
					for (int i=4096-14;i<4096;i++)
						recv_pkt[i]=0;
				read_len -= 14;
				}

				if ( use_eth_sock ) {

					if (recv_pkt[0] / 0x10 != prot3 )
						continue;
					if (recv_pkt[9] != 1 )
						continue;					
				}

				// ADD check for proto

				/*
				// escape if it's ICMP Echo Reply
				if ( prot=1 && sent_icmp->type== 8 && sent_icmp->code==0 && recv_pkt[20]==0 && recv_pkt[20]==0) 
					return read_len;
				*/

				//  check IP addresses
				if ( ( rec_ip->saddr != sent_ip->saddr  ) || ( rec_ip->daddr != sent_ip->daddr  )  )  {
					//printf ("Addresses %08x %08x %08x %08x \n", sent_ip->saddr, rec_ip->saddr, sent_ip->daddr, rec_ip->daddr );
					continue;
				}
				
				// check TCP UDP ports
				if ( prot ==  6 )
					if (  ( sent_tcp->source != rec_tcp->source ) || ( sent_tcp->dest != rec_tcp->dest ) )  {
						//printf ("Ports %04x %04x %04x %04x \n", sent_tcp->source, rec_tcp->source, sent_tcp->dest, rec_tcp->dest );
						continue;
					}
				if ( prot ==  17 )
					if (  ( sent_udp->source != rec_udp->source ) || ( sent_udp->dest != rec_udp->dest ) )  {
						//printf ("Ports %04x %04x %04x %04x \n", sent_udp->source, rec_udp->source, sent_udp->dest, rec_udp->dest );
						continue;
					}

				// next info will be printed later
				icmp_4884_length = recv_pkt[25];
				uint32_t * u32_ptr = recv_pkt + 24;
				icmp_unused = ntohl(* u32_ptr);
				icmp_is_multipart=0;
				icmp_multipart_start_at=0;
				check_if_icmp_multipart(recv_pkt, &icmp_is_multipart, &icmp_multipart_start_at);
				return read_len;

			}


			if ( FD_ISSET(sndsock, &readfds) ) { //continue;
				read_len = recvfrom(sndsock, answer_pkt, 4096, MSG_DONTWAIT,  (const  struct sockaddr *) &dst2, &dst2len); 
				char *ina = rz_ntoa(dst2.sin_addr);
				char *ina2 = rz_ntoa(dst.sin_addr);
				// must be specific for TCP UDP ICMP
				if (prot==6) {
					if  ( 	( 0 == ( tcp_header->tcphdr.syn == 0 && answer_pkt[33] ==18 ) )
						&& 	( 0 == ( (tcp_header->tcphdr.ack == 1) && ( answer_tcp->tcphdr.syn==1 ) ) )
						&&  ( strcmp(ina, ina2) == 0 ) 
						// && ( 0 == ( (tcp_header->tcphdr.syn == 1) && (tcp_header->tcphdr.ack == 0) && ( answer_tcp->tcphdr.syn!=1 )  && (tcp_header->tcphdr.ack != 1) ) )
						&&  ( answer_tcp->tcphdr.dest == tcp_header->tcphdr.source ) 	)

						if ( 0 ==  ( ( answer_ip->saddr != sent_ip->daddr  ) 	
								|| ( answer_ip->daddr != sent_ip->saddr  ) 
								|| ( answer_tcp->tcphdr.source != tcp_header->tcphdr.dest ) 
								|| ( answer_tcp->tcphdr.dest != tcp_header->tcphdr.source ) ) 
						   ) {
							// avoid retransmissions
							if ( 0 == ( avoid_retr && ( ntohl (answer_tcp->tcphdr.seq) < ntohl (tcp_header->tcphdr.ack_seq) ) ) ) {
								*which_sock = 2;				
								return read_len;
							}
						}
				}else if (prot==17) {
						if ( 0 ==  ( ( answer_ip->saddr != sent_ip->daddr  ) 	
								|| ( answer_ip->daddr != sent_ip->saddr  ) 
								|| ( answer_tcp->tcphdr.source != tcp_header->tcphdr.dest ) 
								|| ( answer_tcp->tcphdr.dest != tcp_header->tcphdr.source ) ) 
						   ) {
								*which_sock = 2;				
								return read_len;
							}
				} else if (prot==1) {
						if ( 0 ==  ( ( answer_ip->saddr != sent_ip->daddr ) 	
								||   ( answer_ip->daddr != sent_ip->saddr ) ) 
							) {
								if ( (sent_icmp->type==8 && sent_icmp->code==0 ) 
							      && (sent_icmp->un.echo.id==answer_icmp->un.echo.id 
							      && sent_icmp->un.echo.sequence==sent_icmp->un.echo.sequence) ) {
									*which_sock = 2;				
									return read_len;
								}
							}
				} else {
						if ( 0 ==  ( ( answer_ip->saddr != sent_ip->daddr ) 	
								||   ( answer_ip->daddr != sent_ip->saddr ) )								 
						   ) {
								*which_sock = 2;				
								return read_len;
							}
				}
				
			}
		} else if (prot3 == 6) {

			if ( FD_ISSET(rcvsock6, &readfds) ) { //continue;
				read_len = recvfrom(rcvsock6, recv_pkt, 4096, MSG_DONTWAIT,  (const  struct sockaddr *) &dst26, &dst26len);
				*which_sock = 1;	
				// skip if we are not waiting for ICMP
				if ( recv_only == 1 )
					continue;	

				//  check IP addresses
				if ( compare_in6_addr ( rec_ip6->saddr, sent_ip6->saddr )  || compare_in6_addr ( rec_ip6->daddr, sent_ip6->daddr )   )  {
					continue;
				}

				// check TCP UDP ports
				if ( prot ==  6 )
					if (  ( sent_tcp->source != rec_tcp->source ) || ( sent_tcp->dest != rec_tcp->dest ) )  {
						continue;
					}
				if ( prot ==  17 )
					if (  ( sent_udp->source != rec_udp->source ) || ( sent_udp->dest != rec_udp->dest ) )  {
						continue;
					}

				struct icmp *icp = (struct icmp *) recv_pkt; // (struct icmp *)(recv_pkt + hlen);
				if  ((1 ) ) {
					icmp_4884_length = recv_pkt[4]; // not 44 because no IPv6 header encapsulating ICMPv6 TE msg can be retrieved with socket
					return read_len;
				}


			}


			if ( FD_ISSET(sndsock6b, &readfds) ) { //continue;
				read_len = recvfrom(sndsock6b, answer_pkt, 4096, MSG_DONTWAIT,  (const  struct sockaddr *) &dst26, &dst26len); 
				char ina [50];
				char ina2 [50];
				inet_ntop(AF_INET6, &(dst6.sin6_addr), ina, INET6_ADDRSTRLEN);
				inet_ntop(AF_INET6, &(dst26.sin6_addr), ina2, INET6_ADDRSTRLEN);

				if  ( 
				   ( 0 == (  (sent_tcp->syn == 0) && (answer_tcp->tcphdr.syn==1) && (answer_tcp->tcphdr.ack==1)  )   )
				&& ( 0 == ( (tcp_header->tcphdr.ack == 1) && ( answer_tcp->tcphdr.syn==1 ) ) )
				// && ( 0 == ( (tcp_header->tcphdr.syn == 1) && (tcp_header->tcphdr.ack == 0) && ( answer_tcp->tcphdr.syn!=1 )  && (tcp_header->tcphdr.ack != 1) ) )
				&&  ( strcmp(ina, ina2) == 0 ) 
				&& ( answer_tcp->tcphdr.dest == tcp_header->tcphdr.source ) 	
				)
				{



					if ( 0 == (
						0 
                  	//	   (  compare_in6_addr ( rec_ip6->saddr, sent_ip6->saddr != 0)
					//	|| (  memcmp ( &answer_ip6->daddr, & sent_ip6->saddr, 16) != 0 )
					//	   (compare_in6_addr ( answer_ip6->saddr, sent_ip6->saddr ) )
					//	|| (compare_in6_addr ( answer_ip6->saddr, sent_ip6->saddr ) )
						|| ( answer_tcp->tcphdr.source != tcp_header->tcphdr.dest ) 
						|| ( answer_tcp->tcphdr.dest != tcp_header->tcphdr.source ) 
				           ) 
					   ) {

						// avoid retransmissions
						if ( 0 == ( avoid_retr && ( ntohl (answer_tcp->tcphdr.seq) < ntohl (tcp_header->tcphdr.ack_seq) ) ) ) {
							*which_sock = 2;				
							return read_len;
						}
					}
				}
			}
			

		}
	}
	return -1;

}

static int packet_ok(int read_len, len_and_sockaddr *from_lsa, struct sockaddr *to, int seq)
{
    unsigned char type, code;
    int main_hlen, quoted_hlen;
    int quoted_data_len = read_len;

	// IPv6
	if ( prot3 == 6 ) {
		// print_pkt(recv_pkt+8, 80);
		// Get ICMP
		struct icmp *icp;
		icp = recv_pkt; // (struct icmp *)(recv_pkt + hlen);
		type = icp->icmp_type;
		code = icp->icmp_code;

		if  ((type == 3) && ( (code==0) || (code==1))) {
			return -1;
		}
		else {
			char addr[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &(dst26.sin6_addr), addr, INET6_ADDRSTRLEN);
			if ( (type == 1) && (icmp_du_as_te) ) {	
				return 1;
			}
			else  if ( (type == 128) && (code==0) ) {
				printf("%-39s  ", addr);
				printf("[ICMPv6 Echo Reply]  ") ;
				return 2; 
			}
			else { 						// print type and code
				printf("%-39s  ", addr);
				printf("[ICMPv6 Type %d Code %d]  ", type, code);
				return 2; 
			}
		}


	}
	
    // GET IP
    struct iphdr *ip;
    ip = castToIP(recv_pkt, 0);

    // Test length
	main_hlen = ip->ihl << 2;

	if (read_len < main_hlen + ICMP_MINLEN)
    {
		printf("packet too short (%d bytes)\n", read_len);
		return 0;
	}
    
	read_len -= main_hlen; // get the length of the ICMP
    quoted_data_len -= main_hlen; // Quoted = total - IP_hlen (20 bytes)

    // Test if ICMP OR TCP
    if (ip->protocol == 1) // ICMP
    {
        // Get ICMP
        struct icmp *icp;
        icp = castToICMP(recv_pkt, main_hlen); // (struct icmp *)(recv_pkt + hlen);
        type = icp->icmp_type;
        code = icp->icmp_code;

	if ( (type == 11 && code == 0 ) ) {
		 return -1;
	} else {
		char* addr;
		addr = rz_ntoa(dst2.sin_addr);
		if ( (type == 3) && (icmp_du_as_te) ) {	
				return 1;
			}
		else if ( (type == 0) && (code==0) ) {
				printf("%-15s  ", addr);
				printf("[ICMP Echo Reply]  ") ;
				return 2; 
			}
		else { 						// print type and code
			printf("%-15s  ", addr);
			printf("[ICMP Type %d Code %d]  ", type, code);
			return 2; 
		}
	}

	
        if ((type == ICMP_TIMXCEED && code == ICMP_TIMXCEED_INTRANS)
            || type == ICMP_UNREACH
            || type == ICMP_ECHOREPLY
            )
        {
            quoted_data_len -= 8; // Quoted = rest - ICMP_hlen (8 bytes)

            quoted_ip_offset = main_hlen + SIZEOF_ICMP_HDR;
            
            quoted_ip = castToIP(recv_pkt, quoted_ip_offset); // Quoted IP

            quoted_hlen = quoted_ip->ihl << 2; // Quoted IP header lenght

            quoted_tcp_offset = main_hlen + SIZEOF_ICMP_HDR + quoted_hlen;

            int expected_quoted_ip_len;
            expected_quoted_ip_len = quoted_ip->tot_len << 2;
	
            return (type == ICMP_TIMXCEED ? -1 : code + 1);
        }
    }

}


static void print_delta_ms(unsigned t1p, unsigned t2p) {
	unsigned tt = t2p - t1p;
	printf(" %u.%03u ms ", tt / 1000, tt % 1000);
}


void compare_packets_default(unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) {

	if ( prot3 == 4 )
		compare_ip_packets_default(sent_, 0, def_, 0);
	else if ( prot3 == 6 )
		compare_ip6_packets_default(sent_, 0, def_, 0);
	if (prot == 6 ) {
		compare_tcp_packets_default(sent_ + ip_header_len, 0, def_ + ip_header_len, 0);
		if ( tcp_header_len > 20 )
			compare_tcp_options_default(sent_ + ip_header_len, 0, def_ + ip_header_len, 0);
	} else if ( prot == 17)	{
		compare_udp_packets_default(sent_ + ip_header_len, 0, def_ + ip_header_len, 0);
	} else if ( prot == 1)	{
		compare_icmp_packets_default(sent_ + ip_header_len, 0, def_ + ip_header_len, 0);
	}

	if ( !hide_pay )
	if ( payload_len > 0) {
		print_prot4_name(prot);
		printf("::");
		printf("Payload (");
		print_payload_choice(sent_ + ip_header_len+tcp_header_len, payload_len);
		printf(")  ");
	}	
	if ( (prot==17) && (udp_trailer_len>0) ) {
		printf("UDP");
		printf("::");
		printf("Options (");
		print_payload_as_hex(sent_ + ip_header_len+tcp_header_len+payload_len, udp_trailer_len);
		printf(")  ");
	}
}


void compare_ip6_packets_default(unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) {

	// Pointers
	struct new_my_ipv6_hdr * sent = ((struct new_my_ipv6_hdr *) &sent_[s_offset]);
	struct new_my_ipv6_hdr * def = ((struct new_my_ipv6_hdr *) &def_[d_offset]);


	// IPv6::Version
	if ( sent->version != def->version ) {
		printf("IPv6::Version ");
		printf("(%01x)  ", sent->version);
	}

	// IPv6::TrafficClass
	if ( get_trafficclass(sent) != get_trafficclass(def) ) {
		printf("IPv6::TrafficClass ");
		printf("(%02x)  ", get_trafficclass(sent));
	}	


	// IPv6::Flowlabel
	if ( get_flowlabel(sent) != get_flowlabel(def) ) {
		printf("IPv6::FlowLabel ");
		printf("(%02x)  ", get_flowlabel(sent) );
	}	

	// IPv6::PayloadLength
	if ( sent->payload_len != def->payload_len ) {
		printf("IPv6::PayloadLength ");
		printf("(%04x)  ", ntohs(sent->payload_len));
	}	

	// IPv6::NextHeader
	if ( sent->nexthdr != def->nexthdr ) {
		printf("IPv6::NextHeader ");
		printf("(%02x)  ", sent->nexthdr);
	}	

	// IPv6::Hop_Limit
	if ( 1 ) {
		if (  def->hop_limit != 1 ) {
			printf("!IPv6::HopLimit ");
			printf("(%x)  ", def->hop_limit );
		}	
	}

	// IPv6::SourceAddr
	if ( compare_in6_addr (sent->saddr, def->saddr) != 0 ) {
		char addr1 [INET6_ADDRSTRLEN];
		char addr2 [INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &(sent->saddr), addr1, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(def->saddr), addr2, INET6_ADDRSTRLEN);
		printf("IPv6::SourceAddr ");
		printf("(%s)  ", addr1);
	}	

	// IPv6::DestAddr
	if ( compare_in6_addr (sent->daddr, def->daddr) != 0 ) {
		char addr1 [INET6_ADDRSTRLEN];
		char addr2 [INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &(sent->daddr), addr1, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(def->daddr), addr2, INET6_ADDRSTRLEN);
		printf("IPv6::DestAddr ");
		printf("(%s)  ", addr1);
	}		
	
	return;
}

void compare_ip_packets_default(unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) {
	struct iphdr * sent = ((struct iphdr *) &sent_[s_offset]);
	struct iphdr * def = ((struct iphdr *) &def_[d_offset]);
	struct new_iphdr * sent_n = (struct new_iphdr *)  sent;
	struct new_iphdr * def_n = (struct new_iphdr *)  def;

	// IPv4::Version
	if ( sent->version != def->version ) {
		printf("IP::Version ");
		printf("(%01x)  ", sent->version);
	}

	// IPv4::HeaderLength
	if ( sent->ihl != def->ihl ) {
		printf("IP::HeaderLength ");
		printf("(%01x)  ", sent->ihl);
	}

	// IPv4::DSCP/ECN
	if ( sent->tos != def->tos ) {
		printf("IP::DSCP/ECN ");
		printf("(%02x)  ", sent->tos );
	}

	// IPv4::TotalLenght
	if ( sent->tot_len != def->tot_len ) {
			printf("IP::TotalLenght ");
			printf("(%04x)  ", ntohs(sent->tot_len));
				
	}	

	// IPv4::ID
	if ( sent->id != def->id ) {
		printf("IP::ID ");
		printf("(%04x)  ", ntohs(sent->id) );	
	}	

	// IPv4::Flags
	if ( ( sent_n->res != def_n->res )|| ( sent_n->df != def_n->df ) || ( sent_n->mf != def_n->mf ) ) {
		printf("IP::Flags ");
		printf("(");
		print_ip_header_flags (sent_n);
		printf(")  ");
	}	

	// IPv4::FragOffset
	if ( get_fragoff(sent) != get_fragoff(def) ) {
		printf("IP::FragOffset ");
		printf("(%04x)  ", get_fragoff(sent) );
	}	

	// IPv4::TTL
	if ( sent->ttl != 1 ) {
	// this info is already shown
		printf( "!IP::TTL ");
		printf("(%x)  ", sent->ttl );
	}

	// IPv4::Protocol
	if ( sent->protocol != def->protocol ) {
		printf("IP::Protocol ");
		printf("(%02x)  ", (sent->protocol) );
	}

	// IPv4::SourceAddr
	if ( sent->saddr != def->saddr ) {
		printf("IP::SourceAddr ");
		printf("(");
		print_ip_addr(& sent->saddr);
		printf(")  ");
	}	

	// IPv4::DestAddr
	if ( sent->daddr != def->daddr ) {
		printf("IP::DestAddr ");
		printf("(");
		print_ip_addr(& sent->daddr);
		printf(")  ");
	}	

	// IPv4::Checksum
	if ( ipcheck_wrg != 0 )
		printf("!IP::Checksum (wrg %04x)  ", htons(tcpcheck_wrg) );

}

void compare_tcp_packets_default (unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) {
	// Pointers
	struct tcphdr * sent = ((struct tcphdr *) &sent_[s_offset]);		
	struct tcphdr * def = ((struct tcphdr *) &def_[d_offset]);

	// for better parsing flags and reserved bits
	struct new_tcphdr * sent_n = (struct new_tcphdr *) sent;		
	struct new_tcphdr * def_n = (struct new_tcphdr *) def;		


	// TCP::SourcePort
	if ( sent->source != def->source ) {
		printf("TCP::SourcePort ");
		printf("(%04x)  ", ntohs(sent->source) );
	}	

	// TCP::DestPort

	if ( sent->dest != def->dest ) {
		printf("TCP::DestPort ");
		printf("(%04x)  ", ntohs(sent->dest) );
	}	
	
	// TCP::SeqNumber
	if (!nr || (nr && nr_tb) )
	if ( sent->seq != def->seq ) {
		printf("TCP::SeqNumber ");
		printf("(%08x)  ", ntohl(sent->seq) );
	}	

	// TCP::AckNumber
	if (!nr || (nr && nr_tb) )
	if ( sent->ack_seq != def->ack_seq ) {
		printf("TCP::AckNumber ");
		printf("(%08x)  ", ntohl(sent->ack_seq) );
	}

	// TCP::Offset
	if ( sent->doff != def->doff ) {
		printf("TCP::Offset ");
		printf("(%01x)  ", (sent->doff) );
	}	

	//TCP::Reserved
	if ( sent_n->res != def_n->res ) {
		printf("TCP::Reserved ");
		printf("(");
		print_tcp_header_res (sent_n);
		printf(")  ");
	}	

	//TCP::ECN
	if ( ( sent_n->ns != def_n->ns )|| ( sent_n->ece != def_n->ece ) || ( sent_n->cwr != def_n->cwr ) ) {
		printf("TCP::ECN ");
		printf("(");
		print_tcp_header_ecn (sent_n);
		printf(")  ");
	}	

//TCP::Flags
	if ( sent_n->flags != def_n->flags ) {
		printf("TCP::Flags ");
		printf("(");
		print_tcp_header_flags (sent_n);
		printf(")  ");
	}	


//TCP::WindowSize
	if ( (sent->window != def->window) || ((nr) && (nr_tcp_window_reliable)) ) {
		printf("TCP::Window ");
		printf("(%04x)  ", ntohs(sent->window) );	
	}	

	//TCP::Checksum
	if (!nr || (nr && nr_tb) )
	if ( tcpcheck_wrg != 0 )
		printf("!TCP::Checksum (wrg %04x)  ", htons(tcpcheck_wrg) );

	//TCP::UrgPointer
	if ( sent->urg_ptr != def->urg_ptr ) {
		printf("TCP::UrgPointer ");
		printf("(%04x)  ", ntohs(sent->urg_ptr));		
	}	

	return;
}

void compare_tcp_options_default (unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) {
	unsigned char mod_pkt[DATAGRAM_SIZE];	
	unsigned char mod_pkt_msk [DATAGRAM_SIZE];
	memset(mod_pkt, 0 , DATAGRAM_SIZE);	
	memset(mod_pkt_msk, 0, DATAGRAM_SIZE);	
	compare_tcp_options(def_, d_offset, sent_, s_offset,  tcp_header_len, 0, mod_pkt, mod_pkt_msk, show_all_opt);
}

void compare_udp_packets_default (unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) {
	// Pointers
	struct udphdr * sent = ((struct updhdr *) &sent_[s_offset]);
	struct udphdr * def = ((struct udphdr *) &def_[d_offset]);

	// UDP::SourcePort
	if ( sent->source != def->source ) {
		printf("UDP::SourcePort ");
		printf("(%04x)  ", ntohs(sent->source) );
	}	

	// UDP::DestPort
	if ( sent->dest != def->dest ) {
		printf("UDP::DestPort ");
		printf("(%04x)  ", ntohs(sent->dest) );
	}	

	// UDP::Lentgh
	if ( sent->len != def->len ) {
		printf("UDP::Lentgh ");
		printf("(%04x)  ", ntohs(sent->len) );
	}	

	// UDP::Checksum
	if (!nr || (nr && nr_tb) )
	if ( sent->check == 0 )
		printf("!UDP::Checksum(0)  ");
	else if ( udpcheck_wrg != 0 )
		printf("!UDP::Checksum (wrg %04x)  ", htons(udpcheck_wrg) );

}

void compare_icmp_packets_default (unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) {
	// Pointers
	struct my_icmphdr * sent = ((struct my_icmphdr *) &sent_[s_offset]);
	struct my_icmphdr * def = ((struct my_icmphdr *) &def_[d_offset]);

	// ICMP::Type
	if ( 1 ) {
		printf("ICMP::Type ");
		printf("(%02x)  ", sent->type );
	}	

	// ICMP::Code
	if ( 1 ) {
		printf("ICMP::Code ");
		printf("(%02x)  ", sent->code );
	}	

		// ICMP::Echo_Identifier ICMP::Echo_SeqNumber
	if ( ( (sent->type == 8) || (sent->type == 0) )&& (sent->code == 0) ) {
		printf("ICMP::Echo_Id" );
		printf("(%04x)  ", ntohs(sent->un.echo.id) );
		printf("ICMP::Echo_SeqNumber ");
		printf("(%04x)  ", ntohs(sent->un.echo.sequence) );
	}	
		// ICMP::Frag_MTU
	else if ( (sent->type == 3) && (sent->code == 4) ) {
		printf("ICMP::Frag_MTU ");
		printf("(%04x)  ", ntohs(sent->un.frag.mtu) );
		if ( sent->un.frag.__glibc_reserved != def->un.frag.__glibc_reserved ) {
			printf("ICMP::Frag_Unused ");
			printf("(%04x)  ", ntohs(sent->un.frag.__glibc_reserved ) );
		}
	}
	else  {
		if ( sent->un.gateway != def->un.gateway ) {
			printf("ICMP::Unused ");
			printf("(%08x)  ", ntohs(sent->un.gateway) );	
		}
	}


	// ICMP::Checksum
	if (!nr || (nr && nr_tb) )
 		if ( icmpcheck_wrg != 0 )
			printf("!ICMP::Checksum (wrg %04x)  ", htons(icmpcheck_wrg) );

}




static void compare_ip6_packets (unsigned char * sent_, int s_offset, unsigned char * rec_, int r_offset, int len, unsigned char* mod_, char* mask_, int ttl) {

	// Pointers
	struct new_my_ipv6_hdr * sent = ((struct new_my_ipv6_hdr *) &sent_[s_offset]);
	struct new_my_ipv6_hdr * rec = ((struct new_my_ipv6_hdr *) &rec_[r_offset]);
	struct new_my_ipv6_hdr * mod = ((struct new_my_ipv6_hdr *) &mod_[s_offset]);
	struct new_my_ipv6_hdr * mask = ((struct new_my_ipv6_hdr *) &mask_[s_offset]);


	// IPv6::Version
	if ( mask->version == 0 ) {
		if ( sent->version != rec->version ) {
			//printf(ipv6_fields_names[IP__VERSION]);
			printf("IPv6::Version ");
			printf("(%01x->%01x)  ", sent->version , rec->version );
			mask->version = 1;	
			mod->version = rec->version;
			
		}	
	} else {
		if ( mod->version != rec->version ) {
			printf("IPv6::Version ");
			printf("(%01x->%01x)  ", mod->version , rec->version );
			mod->version = rec->version;
		}
	}


	// IPv6::TrafficClass
	if ( get_trafficclass( mask ) == 0 ) {
		if ( get_trafficclass(sent) != get_trafficclass(rec) ) {
			//printf(ipv6_fields_names[IP__PRIORITY]);
			printf("IPv6::TrafficClass ");
			printf("(%02x->%02x)  ", get_trafficclass(sent) , get_trafficclass(rec) );
			set_trafficclass(mask, 1);	
			set_trafficclass(mod, get_trafficclass(rec));
			
		}	
	} else {
		if ( get_trafficclass(mod) != get_trafficclass(rec) ) {
			printf("IPv6::TrafficClass ");
			printf("(%02x->%02x)  ", get_trafficclass(mod) , get_trafficclass(rec));
			set_trafficclass(mod, get_trafficclass(rec));
		}
	}


	// IPv6::Flowlabel
	if ( get_flowlabel( mask ) == 0 ) {
		if ( get_flowlabel(sent) != get_flowlabel(rec) ) {
			//printf(ipv6_fields_names[IP__PRIORITY]);
			printf("IPv6::FlowLabel ");
			printf("(%02x->%02x)  ", get_flowlabel(sent) , get_flowlabel(rec) );
			set_flowlabel(mask, 1);	
			set_flowlabel(mod, get_flowlabel(rec));		
		}	
	} else {
		if ( get_flowlabel(mod) != get_flowlabel(rec) ) {
			printf("IPv6::FlowLabel ");
			printf("(%02x->%02x)  ", get_flowlabel(mod) , get_flowlabel(rec));
			set_flowlabel(mod, get_flowlabel(rec));
		}
	}

	// IPv6::PayloadLength
	if ( mask->payload_len == 0 ) {
		if ( sent->payload_len != rec->payload_len ) {
			//printf(ipv6_fields_names[IP__payload_len]);
			printf("IPv6::PayloadLength ");
			printf("(%04x->%04x)  ", ntohs(sent->payload_len) , ntohs(rec->payload_len) );
			mask->payload_len = 1;	
			mod->payload_len = rec->payload_len;
			
		}	
	} else {
		if ( mod->payload_len != rec->payload_len ) {
			printf("IPv6::PayloadLength ");
			printf("(%04x->%04x)  ", ntohs(mod->payload_len) , ntohs(rec->payload_len) );
			mod->payload_len = rec->payload_len;
		}
	}

	// IPv6::NextHeader
	if ( mask->nexthdr == 0 ) {
		if ( sent->nexthdr != rec->nexthdr ) {
			//printf(ipv6_fields_names[IP__nexthdr]);
			printf("IPv6::NextHeader ");
			printf("(%02x->%02x)  ", sent->nexthdr , rec->nexthdr );
			mask->nexthdr = 1;	
			mod->nexthdr = rec->nexthdr;
			
		}	
	} else {
		if ( mod->nexthdr != rec->nexthdr ) {
			printf("IPv6::NextHeader ");
			printf("(%02x->%02x)  ", mod->nexthdr , rec->nexthdr );
			mod->nexthdr = rec->nexthdr;
		}
	}

	// IPv6::Hop_Limit
	if ( 1 ) {
		if ( nr ) {
			if ( mask->hop_limit == 0 ) {
				if ( sent->hop_limit != rec->hop_limit ) {
					//printf(ipv6_fields_names[IP__hop_limit]);
					printf("IPv6::HopLimit ");
					printf("(%02x->%02x)  ", sent->hop_limit , rec->hop_limit );
					mask->hop_limit = 1;	
					mod->hop_limit = rec->hop_limit;
			
				}	
			} else {
				if ( mod->hop_limit != rec->hop_limit ) {
						printf("IPv6::HopLimit ");
						printf("(%02x->%02x)  ", mod->hop_limit , rec->hop_limit );
						mod->hop_limit = rec->nexthdr;
				}
			}

		} else { if (  rec->hop_limit != 1 ) {
				//printf(ipv6_fields_names[IP__hop_limit]);
				printf("!IPv6::HopLimit ");
				printf("(%x)  ", rec->hop_limit );
			}	
		}
	}


	// IPv6::SourceAddr
	if (* (int*) & mask->saddr  == 0  ) {
		if ( compare_in6_addr (sent->saddr, rec->saddr) != 0 ) {
			//printf(ipv6_fields_names[IP__nexthdr]);
			char addr1 [INET6_ADDRSTRLEN];
			char addr2 [INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &(sent->saddr), addr1, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(rec->saddr), addr2, INET6_ADDRSTRLEN);
			printf("IPv6::SourceAddr ");
			printf("(%s -> %s)  ", addr1 , addr2 );
			* (int*) & mask->saddr  = 1;	
			mod->saddr = rec->saddr;
			
		}	
	} else {
		if ( compare_in6_addr (mod->saddr, rec->saddr) != 0 ) {
			char addr1 [INET6_ADDRSTRLEN];
			char addr2 [INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &(mod->saddr), addr1, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(rec->saddr), addr2, INET6_ADDRSTRLEN);
			printf("IPv6::SourceAddr ");
			printf("(%s -> %s)  ", addr1 , addr2 );
			mod->saddr = rec->saddr;
		}
	}

	// IPv6::DestAddr
	if (* (int*) & mask->daddr  == 0  ) {
		if ( compare_in6_addr (sent->daddr, rec->daddr) != 0 ) {
			//printf(ipv6_fields_names[IP__nexthdr]);
			char addr1 [INET6_ADDRSTRLEN];
			char addr2 [INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &(sent->daddr), addr1, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(rec->daddr), addr2, INET6_ADDRSTRLEN);
			printf("IPv6::DestAddr ");
			printf("(%s -> %s)  ", addr1 , addr2 );
			* (int*) & mask->daddr  = 1;	
			mod->daddr = rec->daddr;
			
		}	
	} else {
		if ( compare_in6_addr (mod->daddr, rec->daddr) != 0 ) {
			char addr1 [INET6_ADDRSTRLEN];
			char addr2 [INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &(mod->daddr), addr1, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(rec->daddr), addr2, INET6_ADDRSTRLEN);
			printf("IPv6::DestAddr ");
			printf("(%s -> %s)  ", addr1 , addr2 );
			mod->daddr = rec->daddr;
		}
	}
	
	return;
}




static void compare_ip_packets (unsigned char * sent, int s_offset, unsigned char * rec, int r_offset, int len, unsigned char* mod, char* mask, int ttl) {

unsigned char * sent_ = sent;
unsigned char * rec_ = rec;
unsigned char* mod_ = mod;
unsigned char* mask_= mask;

// new code

{

	// Pointers
	struct iphdr * sent = ((struct iphdr *) &sent_[s_offset]);
	struct iphdr * rec = ((struct iphdr *) &rec_[r_offset]);
	struct iphdr * mod = ((struct iphdr *) &mod_[s_offset]);
	struct iphdr * mask = ((struct iphdr *) &mask_[s_offset]);
	// for better parsing flags and reserved bits
	struct new_iphdr * sent_n = (struct new_iphdr *) sent;		
	struct new_iphdr * rec_n = (struct new_iphdr *) rec;		
	struct new_iphdr * mod_n = (struct new_iphdr *) mod;		
	struct new_iphdr * mask_n = (struct new_iphdr *) mask;	


	// IPv4::Version
	if ( mask->version == 0 ) {
		if ( sent->version != rec->version ) {
			printf("IP::Version ");
			printf("(%01x->%01x)  ", sent->version , rec->version );
			mask->version = 1;	
			mod->version = rec->version;
			
		}	
	} else {
		if ( mod->version != rec->version ) {
			printf("IP::Version ");
			printf("(%01x->%01x)  ", mod->version , rec->version );
			mod->version = rec->version;
		}
	}

	// IPv4::HeaderLength
	if ( mask->ihl == 0 ) {
		if ( sent->ihl != rec->ihl ) {
			printf("IP::HeaderLength ");
			printf("(%01x->%01x)  ", sent->ihl , rec->ihl );
			mask->ihl = 1;	
			mod->ihl = rec->ihl;
			
		}	
	} else {
		if ( mod->ihl != rec->ihl ) {
			printf("IP::HeaderLength ");
			printf("(%01x->%01x)  ", mod->ihl , rec->ihl );
			mod->ihl = rec->ihl;
		}
	}

	// IPv4::DSCP/ECN
	if ( mask->tos == 0 ) {
		if ( sent->tos != rec->tos ) {
			printf("IP::DSCP/ECN ");
			printf("(%02x->%02x)  ", sent->tos , rec->tos );
			mask->tos = 1;	
			mod->tos = rec->tos;
			
		}	
	} else {
		if ( mod->tos != rec->tos ) {
			printf("IP::DSCP/ECN ");
			printf("(%02x->%02x)  ", mod->tos , rec->tos );
			mod->tos = rec->tos;
		}
	}

	// IPv4::TotalLenght
	if ( mask->tot_len == 0 ) {
		if ( sent->tot_len != rec->tot_len ) {
			printf("IP::TotalLenght ");
			printf("(%04x->%04x)  ", ntohs(sent->tot_len) , ntohs(rec->tot_len) );
			mask->tot_len = 1;	
			mod->tot_len = rec->tot_len;
			
		}	
	} else {
		if ( mod->tot_len != rec->tot_len ) {
			printf("IP::TotalLenght ");
			printf("(%04x->%04x)  ", ntohs(mod->tot_len) , ntohs(rec->tot_len) );
			mod->tot_len = rec->tot_len;
		}
	}

	// IPv4::ID
	if ( !nr || (nr && nr_tb) ) {
	if ( mask->id == 0 ) {
		if ( sent->id != rec->id ) {
			printf("IP::ID ");
			printf("(%04x->%04x)  ", ntohs(sent->id) , ntohs(rec->id) );
			mask->id = 1;	
			mod->id = rec->id;
			
		}	
	} else {
		if ( mod->id != rec->id ) {
			printf("IP::ID ");
			printf("(%04x->%04x)  ", ntohs(mod->id) , ntohs(rec->id) );
			mod->id = rec->id;
		}
	}
	}


	// IPv4::Flags
	if ( (mask_n->res || mask_n->df || mask_n->mf ) == 0 ) {
		if ( ( sent_n->res != rec_n->res )|| ( sent_n->df != rec_n->df ) || ( sent_n->mf != rec_n->mf ) ) {
			printf("IP::Flags ");
			printf("(");
			print_ip_header_flags (sent_n);
			printf("->");
			print_ip_header_flags (rec_n);
			printf(")  ");
			mask_n->res = 1;	
			mod_n->res = rec_n->res;
			mod_n->df = rec_n->df;			
			mod_n->mf = rec_n->mf;			
		}	
	} else {
		if ( ( mod_n->res != rec_n->res )|| ( mod_n->df != rec_n->df ) || ( mod_n->mf != rec_n->mf ) ) {
			printf("IP::Flags ");
			printf("(");
			print_ip_header_flags (mod_n);
			printf("->");
			print_ip_header_flags (rec_n);
			printf(")  ");
			mod_n->res = rec_n->res;
			mod_n->df = rec_n->df;			
			mod_n->mf = rec_n->mf;	
		}
	}

	// IPv4::FragOffset
	if ( get_fragoff( mask ) == 0 ) {
		if ( get_fragoff(sent) != get_fragoff(rec) ) {
			printf("IP::FragOffset ");
			printf("(%04x->%04x)  ", get_fragoff(sent) , get_fragoff(rec) );
			set_fragoff(mask, 1);	
			set_fragoff(mod, get_fragoff(rec));
			
		}	
	} else {
		if ( get_fragoff(mod) != get_fragoff(rec) ) {
			printf("IP::FragOffset ");
			printf("(%04x->%04x)  ", get_fragoff(mod) , get_fragoff(rec));
			set_fragoff(mod, get_fragoff(rec));
		}
	}

	// IPv4::TTL
	if ( !nr || (nr&&nr_tb_doing)) {
		if ( rec->ttl != 1 ) {
			printf( "!IP::TTL ");
			printf("(%x)  ", rec->ttl );
			if ( !nr || (nr&&nr_tb_doing) ) {
				// correct checksum assuming ttl was 1
				int rec_ttl_offset = rec_ip->ttl - 1;
				int corrected_check = ntohs (rec_ip->check);
				corrected_check += ( rec_ttl_offset * 0x100 );
				corrected_check += corrected_check / 0x10000;
				// printf("chk %04x %04x ", ntohs(rec_ip->check) ,corrected_check);
				// update checksum and ttl		
				rec->check = htons(corrected_check);
				rec->ttl = 1;
			}
		
		}
	} else {
		if ( mask->ttl == 0 ) {
			if ( sent->ttl != rec->ttl ) {
				printf("IP::TTL ");
				printf("(%02x->%02x)  ", sent->ttl , rec->ttl );
				mask->ttl = 1;	
				mod->ttl = rec->ttl;
			
			}	
		} else {
			if ( mod->ttl != rec->ttl ) {
				printf("IP::TTL ");
				printf("(%02x->%02x)  ", mod->ttl , rec->ttl );
				mod->ttl = rec->ttl;
			}
		}
	}


	// IPv4::Protocol
	if ( mask->protocol == 0 ) {
		if ( sent->protocol != rec->protocol ) {
			printf("IP::Protocol ");
			printf("(%02x->%02x)  ", (sent->protocol) , (rec->protocol) );
			mask->protocol = 1;	
			mod->protocol = rec->protocol;
			
		}	
	} else {
		if ( mod->protocol != rec->protocol ) {
			printf("IP::Protocol ");
			printf("(%02x->%02x)  ", (mod->protocol) , (rec->protocol) );
			mod->protocol = rec->protocol;
		}
	}

	// IPv4::Checksum


	// IPv4::SourceAddr
	if ( mask->saddr == 0 ) {
		if ( sent->saddr != rec->saddr ) {
			printf("IP::SourceAddr ");
			printf("(");
			print_ip_addr(& sent->saddr);
			printf("->");
			print_ip_addr(& rec->saddr);
			printf(")  ");
			mask->saddr = 1;	
			mod->saddr = rec->saddr;
			
		}	
	} else {
		if ( mod->saddr != rec->saddr ) {
			printf("IP::SourceAddr ");
			printf("(");
			print_ip_addr(& mod->saddr);
			printf("->");
			print_ip_addr(& rec->saddr);
			printf(")  ");
			mod->saddr = rec->saddr;
		}
	}

	// IPv4::DestAddr
	if ( mask->daddr == 0 ) {
		if ( sent->daddr != rec->daddr ) {
			printf("IP::DestAddr ");
			printf("(");
			print_ip_addr(& sent->daddr);
			printf("->");
			print_ip_addr(& rec->daddr);
			printf(")  ");
			mask->daddr = 1;	
			mod->daddr = rec->daddr;
			
		}	
	} else {
		if ( mod->daddr != rec->daddr ) {
			printf("IP::DestAddr ");
			printf("(");
			print_ip_addr(& mod->daddr);
			printf("->");
			print_ip_addr(& rec->daddr);
			printf(")  ");
			mod->daddr = rec->daddr;
		}
	}




}
    // IPv4::Checksum
    // rooted only
    if ( !nr || (nr && nr_tb) )
	if ( 1 )  {
     
		// check first if checksum itself is correct (will print it later)
		unsigned char ch1, ch2;
		ch1 = rec [r_offset + 10];
		ch2 = rec [r_offset + 11];
		rec [r_offset + 10] = 0;
		rec [r_offset + 11] = 0;
		uint16_t correct_chk_rec = ip_checksum(&rec[r_offset], 20);
		rec [r_offset + 10] = ch1;
		rec [r_offset + 11] = ch2;



	uint16_t sent_chksum = (sent[s_offset + 10])*256+sent[s_offset + 11];	 // keep in count ttl rising at each probe!
	uint16_t sent_chksum_corrected = ( ( sent_chksum + 256*( ttl-1 ) ) );// +  (sent_chksum + 256*( ttl-1 )/ 0x10000) ) % 0x10000;
	// correct for NR
	if ( nr ) 
	sent_chksum_corrected = sent_chksum;

	uint16_t rec_chksum = (rec[r_offset + 10])*256+rec[r_offset + 11];	
	uint16_t mod_chksum = (mod[s_offset + 10])*256+mod[s_offset + 11] ;		// mod is reversed 

	uint16_t diff = (rec_chksum - sent_chksum) - 256*( ttl-1 );

	if ( rec_chksum < sent_chksum + 256*( ttl-1 ))
		diff += 0xffff;
	    uint16_t diff2 = rec_chksum - mod_chksum;
	if ( rec_chksum < mod_chksum )
		diff += 0xffff;
	// correct for NR
	if ( nr ) 
		diff = (rec_chksum - sent_chksum);



	    if ( mask[s_offset +10]== 0) {
		
		if ( diff != 0) {
			
			printf("IP::Checksum ");
			printf("(%04x->%04x)  ", sent_chksum_corrected, rec_chksum);
			memcpy(&mod[s_offset + 10], &rec[r_offset + 10], 2);	
			mask[s_offset +10] = 1;				
		}
	    }
		
	    else { 
	    	if ( diff2 != 0  ) { // rec_chksum != mod_chksum ) {

			printf("IP::Checksum ");
			printf("(%04x->%04x)  ", mod_chksum , rec_chksum);		
			memcpy(&mod[s_offset + 10], &rec[r_offset + 10], 2);
		}
			
	    }
	   
	    uint16_t chk_rec, chk_diff;
	    * ( & chk_rec ) = * (uint16_t *) &rec [r_offset + 10];
	    chk_diff = correct_chk_rec - chk_rec;
	    //uint16_t tmp[2];
		//tmp[0] = correct_chk_rec;
		//tmp[1] = chk_rec;
	    // chk_diff = ip_checksum(&tmp, 2);
	    if (correct_chk_rec < chk_rec)
		chk_diff += 0xffff;				// correct since checksum includes carry
	    if ( (  chk_diff != ipcheck_wrg ) ) {
				// printf("!IP::Checksum (+%04x->+%04x) ", htons(ipcheck_wrg), htons(chk_diff));
				printf("!IP::Checksum ");

				printf("(wrg ");
				if ( ipcheck_wrg == 0 )
					printf("+0000"); //printf("%04x", htons(ipcheck_wrg));
				else
					printf("+%04x", htons(ipcheck_wrg));

				printf("->");

				if ( chk_diff == 0 )
					printf("+0000"); //printf("%04x", htons(chk_diff));
				else
					printf("+%04x", htons(chk_diff));
				
				printf(")  ");

				// update checksum offset so far
				ipcheck_wrg = chk_diff;
			
	    } 
        
    }
	return;
}


static void compare_udp_packets (unsigned char * sent, int s_offset, unsigned char * rec, int r_offset, int len, int sentlen, unsigned char* mod, char* mask)  {

unsigned char * sent_ = sent;
unsigned char * rec_ = rec;
unsigned char* mod_ = mod;
unsigned char* mask_= mask;

// new code
{
	// Pointers
	struct udphdr * sent = ((struct new_my_ipv6_hdr *) &sent_[s_offset]);
	struct udphdr * rec = ((struct new_my_ipv6_hdr *) &rec_[r_offset]);
	struct udphdr * mod = ((struct new_my_ipv6_hdr *) &mod_[s_offset]);
	struct udphdr * mask = ((struct new_my_ipv6_hdr *) &mask_[s_offset]);

	// UDP::SourcePort
	if ( mask->source == 0 ) {
		if ( sent->source != rec->source ) {
			//printf(ipv6_fields_names[IP__source]);
			printf("UDP::SourcePort ");
			printf("(%04x->%04x)  ", ntohs(sent->source) , ntohs(rec->source) );
			mask->source = 1;	
			mod->source = rec->source;
			
		}	
	} else {
		if ( mod->source != rec->source ) {
			printf("UDP::SourcePort ");
			printf("(%04x->%04x)  ", ntohs(mod->source) , ntohs(rec->source) );
			mod->source = rec->source;
		}
	}


	// UDP::DestPort
	if ( mask->dest == 0 ) {
		if ( sent->dest != rec->dest ) {
			//printf(ipv6_fields_names[IP__dest]);
			printf("UDP::DestPort ");
			printf("(%04x->%04x)  ", ntohs(sent->dest) , ntohs(rec->dest) );
			mask->dest = 1;	
			mod->dest = rec->dest;
			
		}	
	} else {
		if ( mod->dest != rec->dest ) {
			printf("UDP::DestPort ");
			printf("(%04x->%04x)  ", ntohs(mod->dest) , ntohs(rec->dest) );
			mod->dest = rec->dest;
		}
	}


	// UDP::Length
	if ( mask->len == 0 ) {
		if ( sent->len != rec->len ) {
			//printf(ipv6_fields_names[IP__len]);
			printf("UDP::Length ");
			printf("(%04x->%04x)  ", ntohs(sent->len) , ntohs(rec->len) );
			mask->len = 1;	
			mod->len = rec->len;
			
		}	
	} else {
		if ( mod->len != rec->len ) {
			printf("UDP::Length ");
			printf("(%04x->%04x)  ", ntohs(mod->len) , ntohs(rec->len) );
			mod->len = rec->len;
		}
	}

	// UDP::Checksum
	// rooted only
	if ( !nr || (nr && nr_tb) )
		check_checksum( sent, 0, rec, 0, len, sentlen, mod,  mask);




}

return;
}

void print_pkt (unsigned char * pkt, int len) {
	printf("\n");
	for (int i= 0; i< len; i++ ) {
		printf("%02x ", pkt[i]);
		if ((i+1) % 20 == 0) 
			printf("\n");			
	}
	printf("\n");
}

void print_pkt_hex (unsigned char * pkt, int len) {
	for (int i= 0; i< len; i++ ) {
		printf("%02x", pkt[i]);
	}
}

void print_pkt_text (unsigned char * pkt, int len) {
	printf("\n");
	for (int i= 0; i< len; i++ ) {
		print_char_if_printable (pkt[i]);
	}
	printf("\n");
}


void print_ip_addr (uint32_t*  addr) {
	uint8_t * a = (uint8_t * ) addr;
	printf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

void print_checksum_offset( uint16_t c) {
	if ( c >= 0x8000 ) {
		uint16_t c_neg = 0xffff -c;
		printf("-%04x",  c_neg);
	}
	else if (c == 0 ){
		printf("+%04x", c);
	} 
	else{
		printf("+%04x", c);
	}

}

void print_ip_header_flags( struct  new_iphdr * ip ) {
	
	int space_needed = 0;

	if ( ip->res == 1)  {
		if  ( space_needed )
			printf(" ");
		printf("Res");
		space_needed = 1;
	}
	if ( ip->df ==1 )  {
		if  ( space_needed )
			printf(" ");
		printf("DF");
		space_needed = 1;
	}
	if ( ip->mf == 1) {
		if  ( space_needed )
			printf(" ");
		printf("MF");
		space_needed = 1;
	}

	if ( ( ip->res || ip->df || ip->mf ) == 0 )
		printf("NoFlag");
}

void print_ip_flags( unsigned char f) {
	char str [20];	
	struct byte_by_bits* B = ( struct byte_by_bits* ) & f;
	int res = 0;
	int df = 0; 
	int mf = 0;
	int space_needed = 0;
	#  if __BYTE_ORDER == __LITTLE_ENDIAN	
		res = B->bit7;
		df  = B->bit6;
		mf  = B->bit5;
	#  elif __BYTE_ORDER == __BIG_ENDIAN
		res = B->bit0;
		df  = B->bit1;
		mf  = B->bit2;
	# endif

	if ( res == 1)  {
		if  ( space_needed )
			printf(" ");
		printf("Res");
		space_needed = 1;
	}
	if ( df ==1 )  {
		if  ( space_needed )
			printf(" ");
		printf("DF");
		space_needed = 1;
	}
	if ( mf == 1) {
		if  ( space_needed )
			printf(" ");
		printf("MF");
		space_needed = 1;
	}

	if ( ( res || df || mf ) == 0 )
		printf("NoFlag");
	
}


void print_last_rtt() {
	// printf("%8.3fms  ", ((float) t2.tv_usec - (float)t1.tv_usec  ) /1000  + ( t2.tv_sec -  t1.tv_sec ) *1000 );
	// show only msecs, no decimal digit
	printf("%5.0fms  ", ((float) t2.tv_usec - (float)t1.tv_usec  ) /1000  + ( t2.tv_sec -  t1.tv_sec ) *1000 );

}

void print_last_rtt_empty() {
	// printf("%8.3fms  ", ((float) t2.tv_usec - (float)t1.tv_usec  ) /1000  + ( t2.tv_sec -  t1.tv_sec ) *1000 );
	// show only msecs, no decimal digit
	printf("         ");

}


int normalize_wayback_ttl( int icmpttl) {
	if ( icmpttl > 128 )
		icmpttl++;
	icmpttl =  icmpttl % 64
;
	if ( icmpttl == 0 )
		icmpttl = icmpttl + 64;
	return icmpttl;
}

void print_wayback_ttl_empty ( ) {
	printf("           ");

}

void print_wayback_ttl( int icmpttl) {
	if (icmpttl / 10 == 0 )
		printf(" ");
	printf("{%d}  ", icmpttl);

}

void print_wayback_ttl_and_norm( int icmpttl) {
	int normicmpttl=  normalize_wayback_ttl(icmpttl);
	printf("{");
	if (icmpttl < 100)
		printf(" ");
	if (icmpttl < 10)
		printf(" ");
	printf("%d", icmpttl);
	printf(",");
	if (normicmpttl < 100)
		printf(" ");
	if (normicmpttl < 10)
		printf(" ");
	printf("%d", normicmpttl);
	printf("}  ");
}




void print_prot4_name (int prot4 ) {
	if ( prot4 == 6 )
		printf ( "TCP");
	else if ( prot4 == 17 )
		printf ( "UDP");
	else if ( prot4 == 1 )
		printf ( "ICMP");
	else 
		printf ( "Proto_%d", prot4);
}


void print_essential_pkt_info( unsigned char * pkt , int payload_len, int recv_only) {
		printf("[");
		print_prot4_name (prot);

		if ( recv_only == 0 ) {  
			if ( prot == 6 ) {
				if ( pkt[13] ) {
					printf(" ");
					print_tcp_header_flags(pkt );
				}
			}

			if ( payload_len != 0 )
				printf(" %d bytes", payload_len);				

			if ( prot3 == 6 )
				printf(" (IPv6)");
		} else {
			printf(" Receive Only");	
		}
		printf( "]  " );
		
}

void print_tcp_header_res( struct new_tcphdr * tcp_n ) {
	uint8_t res = tcp_n->res;
	printf("%01d%01d%01d", (res & 4)>0, (res & 2)>0, (res & 1)>0 );
}


void print_tcp_header_ecn( struct tcphdr * tcph ) {
	char str[40] = "";
	int space_needed = 0;
	// ECN flags
	struct new_tcphdr *  new_tcph  = (struct new_tcphdr  * ) tcph;
	if (new_tcph->ns ) {
		if  ( space_needed )
			printf(" ");
		printf("Ns");
		space_needed = 1;
	}
	if (new_tcph->ece ) {
		if  ( space_needed )
			printf(" ");
		printf("Ecn");
		space_needed = 1;
	}
	if (new_tcph->cwr ) {
		if  ( space_needed )
			printf(" ");
		printf("Cwr");
	
		space_needed = 1;
	}


	// if no flag is set
	if ( space_needed == 0)
		printf("NoFlag");
}



void print_tcp_ecn( struct tcphdr * tcph ) {
	printf("TCP::ECN (");
	print_tcp_header_ecn( tcph );
	printf(")  ");
}

void print_tcp_ack( struct tcphdr * tcph ) {
	printf("TCP::AckNumber (%08x)  ", ntohl(tcph->ack_seq));
}

void print_tcp_header_flags( struct tcphdr * tcph ) {
	char str[40] = "";
	int space_needed = 0;
	
	if (tcph->syn ) {
		if  ( space_needed )
			printf(" ");
		printf("Syn");
		space_needed = 1;
	}
	if (tcph->fin ) {
		if  ( space_needed )
			printf(" ");
		printf("Fin");
		space_needed = 1;
	}
	if (tcph->rst ) {
		if  ( space_needed )
			printf(" ");
		printf("Rst");	
		space_needed = 1;
	}
	if (tcph->ack ) {
		if  ( space_needed )
			printf(" ");
		printf("Ack");
		space_needed = 1;
	}
	if (tcph->psh ) {
		if  ( space_needed )
			printf(" ");
		printf("Psh");
		space_needed = 1;
	}
	if (tcph->urg ) {
		if  ( space_needed )
			printf(" ");
		printf("Urg");
		space_needed = 1;
	}

	// if no flag is set
	if ( space_needed == 0)
		printf("NoFlag");
}

void print_tcp_flags( unsigned char f, unsigned int f_1) {

	if (f & 0x02 )
		printf("Syn ");
	if (f & 0x01 )
		printf("Fin ");
	if (f & 0x04 )
		printf("Rst ");	
	if (f & 0x10 )
		printf("Ack ");
	if (f & 0x08 )
		printf("Psh ");
	if (f & 0x20 )
		printf("Urg ");
	if (f & 0x40 )
		printf("Ecn ");
	if (f & 0x80 )
		printf("Cwr ");
	
	// take into account NS flag
	int ns = f_1 & 0x01;
	if ( ns )
		printf("Ns ");

	if ( (f) || ns )
		printf("\b");

	if ( ( f == 0 ) && ( ns == 0 ) )
		printf("NoFlag");

}

int  get_header_len_by_prot4 () {
	int len = 0;
	if ( prot == 6 )
		len = 20;
	else if ( prot == 17 )			
		len = 8;
	else if ( prot == 11 )			
		len = 8;
	return len;
}

void check_if_icmp_multipart (unsigned char* icmp_pkt, int* is , int* at ) {
	if ( (icmp_pkt[156] == 0x20) && (icmp_pkt[157] == 0x00) ) {
		icmp_is_multipart = 1;
		icmp_multipart_start_at = 157;
	}	
}

void compare_payload (unsigned char * sent, int s_offset, unsigned char * rec, int r_offset, int rec_len, int sent_len, unsigned char* mod, char* mask) {

	// check if already modified
	if ( *(mask + s_offset+tcp_header_len) == 1 )
		sent = mod;

    // correct pointer to print even answer
	struct tcphdr * _rec_tcp = rec+ r_offset;
	struct tcphdr * _sent_tcp = sent + s_offset;

    int rec_headers_len = 0;	
    int sent_headers_len = 0;
	
    int rec_ip_stated_len = 0;
    int sent_ip_stated_len = 0;
    int sent_stated_udp_len = 8;
	int rec_stated_udp_len = 8;

    // get len from IP length field
	if (prot3 == 4 ) {
		sent_ip_stated_len  = ntohs( sent_ip->tot_len ) -20;
		rec_ip_stated_len  = ntohs( rec_ip->tot_len ) -20;
	}
	else if (prot3 == 6)  {
		sent_ip_stated_len = ntohs( sent_ip6->payload_len);
		rec_ip_stated_len = ntohs( rec_ip6->payload_len) ;
	}

    // get layer 4 header length
	if ( prot == 6 ) {
		rec_headers_len = /* rec_ip->ihl * 4 + */ rec_tcp->doff *4 ;
		sent_headers_len = /* sent_ip->ihl * 4 + */ sent_tcp->doff *4 ;
	} else if (prot==17) {
		rec_headers_len = 8 ;
		sent_headers_len = 8 ;
	} else if (prot==1) {
		rec_headers_len = 8 ;
		sent_headers_len = 8 ;
	}

    // get udp length 
    if (prot==17) {
		sent_stated_udp_len = ntohs(sent_udp->len);
		rec_stated_udp_len = ntohs(rec_udp->len);
	}

	int sent_payload_len=0;
	int sent_trailer_len = 0;
	int rec_payload_len=0;
	int rec_trailer_len = 0;
	
    sent_payload_len = sent_ip_stated_len - sent_headers_len;
    if (prot==17) { 
    	sent_payload_len = sent_stated_udp_len - sent_headers_len;
    	sent_trailer_len = sent_ip_stated_len - sent_stated_udp_len; 
    }

    // check for multipart ICMP
    if ( icmp_is_multipart ) { 
    	int rec_len_before_icmp_multipart = rec_len - (icmp_multipart_start_at -1 -28);
    	if ( rec_len > rec_len_before_icmp_multipart ) {
    	rec_len = rec_len_before_icmp_multipart;
    	}
    }

	// min between len calculated from icmp packet length and from ip header field
	int whole_rec_len = 0;
	int whole_rec_payload_len = 0;
	int whole_rec_trailer_len = 0;
	if ( rec_ip_stated_len <= rec_len ) {
		rec_len = rec_ip_stated_len;
		whole_rec_len = 1;
	}

    if (prot==17) {
	    if ( (whole_rec_len==0) && (rec_stated_udp_len <= rec_len) ) {
	    	rec_len = rec_stated_udp_len ;
			whole_rec_payload_len = 1;
			whole_rec_trailer_len = 0;
		}
	} else {
		whole_rec_trailer_len = whole_rec_len;
		whole_rec_payload_len = whole_rec_len;
	}


    

	// check if not possible to get tcp header length
	if ( ( prot == 6  ) &&  ( rec_headers_len < 20 ) )
			rec_payload_len = 0;
		else {
			rec_payload_len = rec_len - rec_headers_len;
			if (prot==17) {
				rec_trailer_len = rec_len - rec_stated_udp_len;
				if (rec_trailer_len < 0 )
					rec_trailer_len = 0;
				rec_payload_len = rec_len - rec_headers_len - rec_trailer_len;
				//printf("rec_len %d trailer %d pay %d\n",rec_len, rec_trailer_len,rec_payload_len);
			}

		}


	// check if len is fakely greater than sent len
	int min_payload_len = sent_payload_len;
	if (min_payload_len > rec_payload_len)
		min_payload_len = rec_payload_len;

    int min_trailer_len = sent_trailer_len;
	if (min_trailer_len > rec_trailer_len)
		min_trailer_len = rec_trailer_len;

	if ( rec_payload_len > 0 ) {
		if (    ( (whole_rec_payload_len == 1) && (sent_payload_len != rec_payload_len) )
		    ||  ( memcmp( sent + s_offset + sent_headers_len, rec + r_offset + rec_headers_len, min_payload_len ) != 0 )   ) {
			print_prot4_name(prot);
			printf("::");
			printf("Payload ");	
			printf("(");
			print_payload_choice(sent + s_offset + sent_headers_len, payload_len);
			printf(" -> ");
			print_payload_choice(rec + r_offset + rec_headers_len, rec_payload_len);	
			printf(")  ");
		}
		else
			; 
	}
	else
		; 

	if ( rec_trailer_len > 0 ) {
		if (    ( (whole_rec_trailer_len == 1) && (sent_trailer_len != rec_trailer_len) )
		    ||  ( memcmp( sent + s_offset + sent_headers_len + sent_payload_len, rec + r_offset + rec_headers_len + rec_payload_len, min_trailer_len ) != 0 )   ) {
			print_prot4_name(prot);
			printf("::");
			printf("Options ");	
			printf("(");
			print_payload_choice(sent + s_offset + sent_headers_len + sent_payload_len, sent_trailer_len);
			printf(" -> ");
			print_payload_choice(rec + r_offset + rec_headers_len + rec_payload_len, rec_trailer_len);	
			printf(")  ");
		}
		else
			; 
	}
	else
		; 


	// store new payload only if whole payload and trailer has been received
	if (whole_rec_len == 1) {
		*(mask + s_offset+sent_headers_len) = 1;
		memcpy(mod+s_offset+sent_headers_len, rec+r_offset+rec_headers_len, rec_payload_len + rec_trailer_len);
	}
		
}


void print_payload_choice (unsigned char* pay, int len) {
	if ( 	((prot == 6) && (dest_port == 80) && (pay_as_hex==0)) 
	     || (pay_as_text == 1) 					)  {
		print_payload_as_text(pay, len);
	} else   { // pay_as_hex
		if ((prot == 6) && (dest_port == 443 ) )
			print_c_s_hello (pay, len);
			print_payload_as_hex(pay, len);
	}
}

void print_payload_as_text ( unsigned char* s, int len ) {
	printf("\"");
	for (int i = 0; i<len; i++)
		print_char_if_printable(* (s + i));
	printf("\"");
}

void print_payload_as_hex ( unsigned char* pkt, int len ) {
	for (int i= 0; i< len; i++ ) {
		printf("%02x", pkt[i]);
	}
}

void print_c_s_hello ( unsigned char* s, int len) {
	if ( len >= 6 )
		if ( s[5] == 1 )
			printf("Client Hello ");
		if ( s[5] == 2 )
			printf("Server Hello ");
}

void print_char_if_printable (char c) {
	static int space = 0;
	if ( c >= 32) {
		printf("%c", c);
		space = 0;
	}
	else {
		if (space != 1 ) {
			printf(" ");
			space = 1;
		}
	}

}

void print_payload (unsigned char * sent, int s_offset, unsigned char * rec, int r_offset, int len, int sentlen, unsigned char* mod, char* mask, int dest_pay_1, int dest_pay_printable, int dest_pay, int dest_pay_choice) {

	// correct pointer to print even answer
	struct tcphdr * rec_tcp = rec+ r_offset;

	int rec_headers_len = /* rec_ip->ihl * 4 + */ rec_tcp->doff *4 ;
	int rec_payload_len;

	// check if not possible to get tcp header length
	if ( rec_headers_len < 20 )
		rec_payload_len = 0;
	else 		
		rec_payload_len = len  - rec_headers_len;
	if ( rec_payload_len > 0 ) {
		unsigned char c= '\0';
		if ( dest_pay_printable == 1 ) {
			printf("[");			
			for (int i = 0; i<rec_payload_len; i++) {
				c = * (rec + r_offset + rec_headers_len +i);
				if ( c >= 32) {
					printf("%c", c);
				}
				else {
					printf(" ");
				}
			}
			printf("]  ");
		}
		else if (dest_pay_1 == 1) {
			printf("[");			
			for (int i = 0; i<rec_payload_len; i++) {
				c = * (rec + r_offset + rec_headers_len +i);
				if ( c >= 32) {
					printf("%c", c);
				}
				else {
					break;
				}
			}
			printf("]  ");

		}
		else if (dest_pay == 1){
			printf("\n[");
			for (int i = 0; i<rec_payload_len; i++) {
				c = * (rec + r_offset + rec_headers_len +i);
				printf("%c", c);
			}
			printf("]\n");
		}
		else if (dest_pay_choice == 1){
			print_prot4_name(prot);
			printf("::");
			printf("Payload ");	
			printf("(");
			print_payload_choice(rec + r_offset + rec_headers_len, rec_payload_len);
			printf(")  ");			
		}
	}
}



void print_tcp_option(struct tcp_option * a, struct tcp_option * b) {

}

void print_tcp_option_name(struct tcp_option * a) {
	switch ( a->kind ) {
		case 0:
			printf("EndOfOptions")	;
			break;
		case 1:
			printf("NOP");
			break;
		case 2:
			printf("MSS");
			break;
		case 3:
			printf("WindowScale");
			break;
		case 4:
			printf("Sack_Perm");
			break;
		case 5:
			printf("Sack");
			break;
		case 8:
			printf("Timestamp");
			break;
		case 30:
			printf("MPTCP");
			break;
		default:
			printf("%d", a->kind);
			break;
	}
	return;
}

void print_tcp_option_data(struct tcp_option * a) {
	switch ( a->kind ) {
		case 2: 
			{
			struct tcp_option_mss * mss = (struct tcp_option_mss *) a;
			printf("%04x", ntohs(mss->mss));
			break;
		}
		case 3:
			{
			struct tcp_option_windowscale * ws = (struct tcp_option_windowscale *)  a;
			printf("%02x", ws->value);
			break;
		}
		case 5:	
			// SACK			
			for (int i=0; i<4; i++)
				printf("%02x", * (&a->value +i) );
			printf(",");
			
			for (int i=4; i<8; i++)
 				printf("%02x", * (&a->value +i) );
			break;

		default:
			for (int i=0; i< a->len -2; i++)
				printf("%02x", * (&a->value +i) );
			break;
	}
	return;
}


void compare_tcp_options (unsigned char * sent, int s_offset, unsigned char * rec, int r_offset, int len, int sentlen, unsigned char* mod, char* mask, int showall)
{	
	// First check for sent options, if unmodified, modified or missing
	// Then will check for added options
	int iterator1 = 20, iterator2 = 20;;
    	int nop_count_a = 0;
	int nop_count_b = 0;
	int modified=0;	
	unsigned char* previous;

	if ( mask[s_offset +20 ] == 0) {
		previous = sent;	
	}
	else {
		sent = mod;
		//s_offset = r_offset;
	}

	int rec_header_len = ( rec[r_offset + 12 ] - rec[r_offset + 12 ] % 16 ) /16 *4;
	int sent_header_len = ( sent[s_offset + 12] -  sent[s_offset + 12] % 16) /16 *4;

	if (len < rec_header_len )
		return;		// not all the tcp header is quoted
	
	if ( rec_header_len < 20 )
		return;		// wrong header length

	len = rec_header_len;

	//	if (sentlen > sent_header_len)	
	sentlen = sent_header_len;
	
	// loop for missing and changed tcp options
	while ( iterator1 < sentlen ) {				// use sent TCP->HDR_LEN
		uint8_t* a = &sent[s_offset + iterator1];
		struct tcp_option * opta = (struct tcp_option *) a;
		
		if ( opta->kind == 0 ) {
				
				break;
			}

		if ( opta->kind == 1 ) {
				iterator1++; 
				continue;
			}
		
		// check due only for wrong cutstom arguments			
		if ( opta->len == 0 ) {
				return;
		}

		// check the whole option is quoted in the header
		if ( opta->len + iterator1 > sentlen ) {
				;//break;
		}
		
 		iterator2 = 20;
		int opt_found = 0; 
		while ( ( iterator2 < len ) && opt_found == 0 ){
			
			uint8_t* b = &rec[r_offset + iterator2];
			struct tcp_option * optb = (struct tcp_option *) b;
		
			if ( optb->kind == 0 ) {
				break;
			}
			if ( optb->kind == 1 ) {
				
				iterator2++; 
				continue;
			}
			
			// check due only for wrong custom arguments			
			if ( optb->len == 0 ) {
				return;
			}

			// check the whole option is quoted in the header
			if ( optb->len + iterator2 > len ) {
					;//break;
			}

			if ( opta->kind == optb->kind ) {
				opt_found = 1;
				if ( (memcmp(& opta->value, & optb->value, opta->len - 2) != 0) 
				   ||  ( 	opta->len != optb->len ) )			{
				
					if ( !hide_all_opt_changed ) 
					if ( (hide_opt_changed == 0) || ( opta->kind == 2) || ( (nr_tcp_ws_reliable) && ( opta->kind == 3) ) ) {
						printf("TCP::Option_");
						print_tcp_option_name(a);
						if ( hide_opt_val == 0 ) {
							printf(" (");
							print_tcp_option_data(a);
							printf("->");
							print_tcp_option_data(b);
							printf(")  ");
						}
						else
							printf("  ");
					}
					modified = 1;
				}
				else {
					// same option, same length, same value
					if ( showall == 1 ) {
						printf("=TCP::Option_");
						print_tcp_option_name(a);
						printf("  ");
					}	
				}
				// MP CAPABLE: to be moved somewhere else !!!
				if ( optb->kind == 30 ) {
					struct tcp_option_mpcapable * mp = (struct tcp_option_mpcapable *) optb;
					if ( ( mp->len == 12 ) && (mp->subtype == 0 ) ) {
						mp_cap_syn_ack = 1;
						mp_cap_syn_ack_key = mp->key1;
					}
						
				}
				// FAST OPEN 34: to be moved somewhere else !!!
				if ( optb->kind == 34 ) {
					struct tcp_option_fo * mp = (struct tcp_option_fo *) optb;
					fo_cookie_len = mp->len;	
					memcpy ( fo_cookie, mp->cookie, fo_cookie_len);
				}

				// FAST OPEN 254: to be moved somewhere else !!!
				if ( optb->kind == 254 ) {
					struct tcp_option_fo2 * fo2 = (struct tcp_option_fo2 *) optb;
					fo_cookie_len = fo2->len -2 ;	
					memcpy ( fo_cookie, fo2->cookie , fo_cookie_len);
				}

				break;
			}
			else 
				iterator2 += optb->len;
		}
		if ( opt_found != 1 ) {
			printf("-TCP::Option_");
			print_tcp_option_name(a);
			printf("  ");
			modified = 1;
		}
		iterator1 += opta->len;

	}
	
	// check option NOP count
	iterator2 = 20;	
	while ( iterator2 < len ) {
		uint8_t* b = &rec[r_offset + iterator2];
		struct tcp_option * optb = (struct tcp_option *) b;
		
		if ( optb->kind == 0 ) {
				break;
			}

		if ( optb->kind == 1 ) {
				nop_count_b++;
				iterator2++; 
				continue;
		}
		iterator2 += optb->len;
	}

	iterator1 = 20;	
	while ( iterator1 < sentlen ) {
		uint8_t* a = &sent[s_offset + iterator1];
		struct tcp_option * opta = (struct tcp_option *) a;
		
		if ( opta->kind == 0 ) {
				break;
			}

		if ( opta->kind == 1 ) {
				nop_count_a++;
				iterator1++; 
				continue;
		}
		iterator1 += opta->len;
	}

	int nop_count_diff = nop_count_b - nop_count_a;
	if ( nop_count_diff != 0 ) {
		printf("TCP::Option_NOP (%+d)  ", nop_count_diff );
	}


	
	// loop for added tcp options
	iterator1 = 20; iterator2 = 20;
	while ( iterator2 < len ) {
		uint8_t* b = &rec[r_offset + iterator2];
		struct tcp_option * optb = (struct tcp_option *) b;


		if ( optb->kind == 0 ) {
			break;
		}
		
		// check the whole option is quoted in the header
		if ( optb->len + iterator2 > len ) {
				;//break;
		}

		if ( optb->kind == 1 ) {		
			iterator2++; 
			continue;
			}

 		iterator1 = 20;
		int opt_found = 0; 

		while ( ( iterator1 < sentlen) && (opt_found == 0 ) ) {
			uint8_t* a = &sent[s_offset + iterator1]; 
			struct tcp_option * opta = (struct tcp_option *) a;


			if ( opta->kind == 0 ) {
					break;
				}

			if ( opta->kind == 1 ) {
					iterator1++; 
					continue;
				}

			// check the whole option is quoted in the header
			if ( opta->len + iterator1 > sentlen ) {
					;//break;
			}

			if ( opta->kind == optb->kind ) {
				opt_found = 1;
				break;
			}
			else 
				iterator1 += opta->len;
		}
		if ( opt_found != 1 )  {
			printf("+TCP::Option_");

			print_tcp_option_name(optb);
			
			if (      (!nr) || (nr && !nr_tcp_opt_cd) || (    nr && nr_tcp_opt_cd  && (   (optb->kind == 2) || ( (nr_tcp_ws_reliable) && ( optb->kind == 3) )  )    )     )
				if ( optb->len > 2 ) { 
					printf(" (");
					print_tcp_option_data(optb);
					printf(")  ");
				} else
					printf("  ");
			else 
				printf("  ");
			modified = 1;
		}
		iterator2 += optb->len;

	}

	// store so far modified options field
	if ( modified == 1 ) { 
		mask[s_offset +20] = 1;		// the field has been modified
		memcpy( &mod[s_offset +20], &rec[r_offset +20], len -20);	// store the field modified so far
		memcpy ( &mod[s_offset+12],  &rec[r_offset +12],1);
	}

}


static void compare_tcp_packets (unsigned char * sent, int s_offset, unsigned char * rec, int r_offset, int len, int sentlen, unsigned char* mod, char* mask) {

	// guess actual received tcp length
	int actual_len = len;
	if ( actual_len > sentlen )
		actual_len = rec[r_offset + 12] / 4;


	unsigned char * sent_ = sent;
	unsigned char * rec_ = rec;
	unsigned char* mod_ = mod;
	unsigned char* mask_= mask;


	// new code
	{
	// Pointers
	struct tcphdr * sent = ((struct tcphdr *) &sent_[s_offset]);		
	struct tcphdr * rec = ((struct tcphdr *) &rec_[r_offset]);
	struct tcphdr * mod = ((struct tcphdr *) &mod_[s_offset]);
	struct tcphdr * mask = ((struct tcphdr *) &mask_[s_offset]);
	
	// for better parsing flags and reserved bits
	struct new_tcphdr * sent_n = (struct new_tcphdr *) sent;		
	struct new_tcphdr * rec_n = (struct new_tcphdr *) rec;		
	struct new_tcphdr * mod_n = (struct new_tcphdr *) mod;		
	struct new_tcphdr * mask_n = (struct new_tcphdr *) mask;		

//print_pkt(sent, 40);

	// TCP::SourcePort
	if  ( actual_len >= 2 ) {
		if ( mask->source == 0 ) {
			if ( sent->source != rec->source ) {
				printf("TCP::SourcePort ");
				printf("(%04x->%04x)  ", ntohs(sent->source) , ntohs(rec->source) );
				mask->source = 1;	
				mod->source = rec->source;			
			}	
		} else {
			if ( mod->source != rec->source ) {
				printf("TCP::SourcePort ");
				printf("(%04x->%04x)  ", ntohs(mod->source) , ntohs(rec->source) );
				mod->source = rec->source;
			}
		}
	}

	// TCP::DestPort
	if  ( actual_len >= 4 ) {
		if ( mask->dest == 0 ) {
			if ( sent->dest != rec->dest ) {
				printf("TCP::DestPort ");
				printf("(%04x->%04x)  ", ntohs(sent->dest) , ntohs(rec->dest) );
				mask->dest = 1;	
				mod->dest = rec->dest;			
			}	
		} else {
			if ( mod->dest != rec->dest ) {
				printf("TCP::DestPort ");
				printf("(%04x->%04x)  ", ntohs(mod->dest) , ntohs(rec->dest) );
				mod->dest = rec->dest;
			}
		}
	}

	// TCP::SeqNumber
	// rooted only
	if ( !nr || (nr && nr_tb) )
	if  ( actual_len >= 8 ) {
		if ( mask->seq == 0 ) {
			if ( sent->seq != rec->seq ) {
				printf("TCP::SeqNumber ");
				printf("(%08x->%08x)  ", ntohl(sent->seq) , ntohl(rec->seq) );
				mask->seq = 1;	
				mod->seq = rec->seq;			
			}	
		} else {
			if ( mod->seq != rec->seq ) {
				printf("TCP::SeqNumber ");
				printf("(%08x->%08x)  ", ntohl(mod->seq) , ntohl(rec->seq) );
				mod->seq = rec->seq;
			}
		}
	}

	// TCP::AckNumber
	// rooted only
	if ( !nr || (nr && nr_tb) )
	if  ( actual_len >= 12 ) {
		if ( mask->ack_seq == 0 ) {
			if ( sent->ack_seq != rec->ack_seq ) {
				printf("TCP::AckNumber ");
				printf("(%08x->%08x)  ", ntohl(sent->ack_seq) , ntohl(rec->ack_seq) );
				mask->ack_seq = 1;	
				mod->ack_seq = rec->ack_seq;			
			}	
		} else {
			if ( mod->ack_seq != rec->ack_seq ) {
				printf("TCP::AckNumber ");
				printf("(%08x->%08x)  ", ntohl(mod->ack_seq) , ntohl(rec->ack_seq) );
				mod->ack_seq = rec->ack_seq;
			}
		}
	}

	// TCP::Offset
	if  ( actual_len >= 13 ) {
		if ( mask->doff == 0 ) {
			if ( sent->doff != rec->doff ) {
				printf("TCP::Offset ");
				printf("(%01x->%01x)  ", (sent->doff) , (rec->doff) );
				mask->doff = 1;	
				mod->doff = rec->doff;			
			}	
		} else {
			if ( mod->doff != rec->doff ) {
				printf("TCP::Offset ");
				printf("(%01x->%01x)  ", (mod->doff) , (rec->doff) );
				mod->doff = rec->doff;
			}
		}
	}

	//TCP::Reserved
	if  ( actual_len >= 13 ) {
		if ( mask_n->res == 0 ) {
			if ( sent_n->res != rec_n->res ) {
				printf("TCP::Reserved ");
				printf("(");
				print_tcp_header_res (sent_n);
				printf("->");
				print_tcp_header_res (rec_n);
				printf(")  ");
				mask_n->res = 1;	
				mod_n->res = rec_n->res;			
			}	
		} else {
			if ( mod_n->res != rec_n->res ) {
				printf("TCP::Reserved ");
				printf("(");
				print_tcp_header_res (mod_n);
				printf("->");
				print_tcp_header_res (rec_n);
				printf(")  ");
				mod_n->res = rec_n->res;
			}
		}
	}

	//TCP::ECN
	if  ( actual_len >= 14 ) {
		if ( (mask_n->ns || mask_n->cwr || mask_n->ece ) == 0 ) {
			if ( ( sent_n->ns != rec_n->ns )|| ( sent_n->ece != rec_n->ece ) || ( sent_n->cwr != rec_n->cwr ) ) {
				printf("TCP::ECN ");
				printf("(");
				print_tcp_header_ecn (sent_n);
				printf("->");
				print_tcp_header_ecn (rec_n);
				printf(")  ");
				mask_n->ns = 1;	
				mod_n->ns = rec_n->ns;
				mod_n->ece = rec_n->ece;			
				mod_n->cwr = rec_n->cwr;			
			}	
		} else {
			if ( ( mod_n->ns != mod_n->ns )|| ( mod_n->ece != rec_n->cwr ) || ( mod_n->ece != rec_n->cwr ) ) {
				printf("TCP::ECN ");
				printf("(");
				print_tcp_header_ecn (mod_n);
				printf("->");
				print_tcp_header_ecn (rec_n);
				printf(")  ");
				mod_n->ns = rec_n->ns;
				mod_n->ece = rec_n->ece;			
				mod_n->cwr = rec_n->cwr;	
			}
		}
	}

	//TCP::Flags
	if  ( actual_len >= 14 ) {
		if ( mask_n->flags == 0 ) {
			if ( sent_n->flags != rec_n->flags ) {
				printf("TCP::Flags ");
				printf("(");
				print_tcp_header_flags (sent_n);
				printf("->");
				print_tcp_header_flags (rec_n);
				printf(")  ");
				mask_n->flags = 1;	
				mod_n->flags = rec_n->flags;			
			}	
		} else {
			if ( mod_n->flags != rec_n->flags ) {
				printf("TCP::Flags ");
				printf("(");
				print_tcp_header_flags (mod_n);
				printf("->");
				print_tcp_header_flags (rec_n);
				printf(")  ");
				mod_n->flags = rec_n->flags;
			}
		}
	}


	//TCP::WindowSize
	if ( !nr || (nr && nr_tb) || ((nr) && (nr_tcp_window_reliable) ) )
	if  ( actual_len >= 16 ) {
		if ( mask->window == 0 ) {
			if ( sent->window != rec->window ) {
				printf("TCP::Window ");
				printf("(%04x->%04x)  ", ntohs(sent->window) , ntohs(rec->window) );
				mask->window = 1;	
				mod->window = rec->window;			
			}	
		} else {
			if ( mod->window != rec->window ) {
				printf("TCP::Window ");
				printf("(%04x->%04x)  ", ntohs(mod->window) , ntohs(rec->window) );
				mod->window = rec->window;
			}
		}
	}

	//TCP::Checksum
	// rooted only
	if ( !nr || (nr && nr_tb) )
	if  ( actual_len >= 18 ) {
		check_checksum( sent, 0, rec, 0, len, sentlen, mod,  mask);
	}

	//TCP::UrgPointer
	if  ( actual_len >= 20 ) {
		if ( mask->urg_ptr == 0 ) {
			if ( sent->urg_ptr != rec->urg_ptr ) {
				printf("TCP::UrgPointer ");
				printf("(%04x->%04x)  ", ntohs(sent->urg_ptr) , ntohs(rec->urg_ptr) );
				mask->urg_ptr = 1;	
				mod->urg_ptr = rec->urg_ptr;			
			}	
		} else {
			if ( mod->urg_ptr != rec->urg_ptr ) {
				printf("TCP::UrgPointer ");
				printf("(%04x->%04x)  ", ntohs(mod->urg_ptr) , ntohs(rec->urg_ptr) );
				mod->urg_ptr = rec->urg_ptr;
			}
		}
	}


	//ws urg ch



	}
	 return;
}

static int common_tracebox_main(char *url_or_ip)
{
	// delay needed?
	if ( tb_delay != 0 )
		sleep(tb_delay);

	

	// correct inside NR abuse of recv_pkt
	{
	rec_ip = ((struct iphdr *) &recv_pkt[28]);
	rec_ip6 = ((struct my_ipv6_hdr *) &recv_pkt[8] );
	rec_tcp = (struct t *) (&recv_pkt[28] + sizeof (struct iphdr)   );
	rec_udp = ((struct udphdr *) ( &recv_pkt[28] + 20 ));	
	if (prot==6) {
		rec_tcp = ( (struct tcphdr *) (recv_pkt + sizeof (struct my_ipv6_hdr) + 8 ) );
		rec_udp = ((struct udphdr *) ( recv_pkt +  sizeof (struct my_ipv6_hdr) + 8 ));
	}
	}



	// constant and variables to handle probes
	int max_ttl = ttl_max;
	int nprobes = row_stars;
	int first_ttl = ttl_min;
    	int stars_max = max_stars;

   	int path_length;
	unsigned pausemsecs = 0;
	char *dest_str;
    
	len_and_sockaddr *from_lsa;
	struct sockaddr *lastaddr;
	char * lastaddrseen[20];
	struct sockaddr *to;

    // set destination address
	dst.sin_addr.s_addr = inet_addr(url_or_ip);
	dst.sin_family = AF_INET;
	dst.sin_port = htons( 80 );
	
	raw_sockets_created = create_raw_sockets();
	
	if ( raw_sockets_created != 1 )
		return;

	// only if it's the first time or 3rd layer protolo is changed
	if ( got_ifaddrs == 0 || new_prot3 == 1 || new_ifaddrs == 1 )
		got_ifaddrs = get_ifaddrs ();

	
	// bind to iface or addr
	if ( got_ifaddrs == 0 || new_prot3 == 1 || new_ifaddrs == 1 ) {
		if (prot3 == 4 ) {
			struct sockaddr_in addr4;
			addr4.sin_addr.s_addr = inet_addr(local_addr);
	    		addr4.sin_family = AF_INET;
			if( bind(sndsock,(struct sockaddr *)&addr4 , sizeof(addr4) ) <0 )
			if( bind(rcvsock,(struct sockaddr *)&addr4 , sizeof(addr4) ) <0 )
			if( bind(sndsocku,(struct sockaddr *)&addr4 , sizeof(addr4) ) <0 )
				;
		}
		else if (prot3 == 6) {
			struct sockaddr_in6 addr6;
			inet_pton(AF_INET6, local_addr, (void *)&addr6.sin6_addr.s6_addr);
			addr6.sin6_flowinfo = 0;
		    	addr6.sin6_family = AF_INET6;
			addr6.sin6_scope_id = 0;
			//client6.sin6_addr = in6addr_any;
			if( bind(sndsock6,(struct sockaddr *)&addr6 , sizeof(addr6)) <0) 
			if( bind(rcvsock6,(struct sockaddr *)&addr6 , sizeof(addr6)) <0) 
			if( bind(sndsock6b,(struct sockaddr *)&addr6 , sizeof(addr6)) <0) 
				;
		}
	}



	// once got if addr print "traceboxing from ... to ..."
	printf("traceboxing from  %s  to  %s  \n", local_addr, url_or_ip);


    // PROCESS ID
	ident = getpid();
    
	// Revert to non-privileged user after opening sockets
	from_lsa = malloc(sizeof(dest_lsa));    	
	
	lastaddr = malloc(sizeof(struct sockaddr)); 

	to =  malloc(sizeof(struct sockaddr)); 
	seq = 0;
	   
    int got_dest;
   	got_dest = 0;
    int stars_counter = 0;
    
	// cleans modded packet and mask
	memset(mod_pkt, 0 , DATAGRAM_SIZE);	
	memset(mod_pkt_msk, 0, DATAGRAM_SIZE);	

    // set default packet
	set_default_fields(sent_datagram, seq, ttl, 1, 0);

	// save default packet
	memcpy(default_pkt, sent_datagram, ip_header_len + tcp_header_len);


	// set custom fields
	set_custom_fields(sent_datagram, seq, ttl, 1, 0);
	//print_pkt(sent_datagram, 70);
	
	// calculate new lengths
	// TCP
	if ( prot == 6 ) {	
		// add padding to TCP header if needed			
		if ( off_tcp_pad == 0 ) {
			int padding =  4 - ( tcp_header_len % 4 );
			if ( padding != 4 )
				tcp_header_len += padding;		
		}
		if ( off_tcplen != 1) {
			// set correct lengths		
			tcp_header->tcphdr.doff = tcp_header_len  / 4;
		} 
	}
	// UDP
	else if ( prot == 17 ) {
		if ( off_udplen != 1) {
			udp_header->len = ntohs(sizeof ( struct udphdr ) + payload_len );
		}
	}

	// IP
	if ( prot3 == 4 ) {
		if ( off_iplen != 1 ) {
			if ( prot == 6 ) {	
				sent_ip->tot_len = ntohs (ip_header_len + tcp_header_len + payload_len);
			} else if ( prot == 17 ) {
				sent_ip->tot_len = ntohs (ip_header_len + sizeof ( struct udphdr ) + payload_len + udp_trailer_len);
			} else {
				sent_ip->tot_len = ntohs (ip_header_len + tcp_header_len + payload_len);
			}
		}
	} else if (prot3 == 6 ) {
		if ( off_iplen != 1 ) {
			if ( prot == 6 ) {	
				sent_ip6->payload_len = ntohs (tcp_header_len + payload_len);
			} else if ( prot == 17 ) {
				sent_ip6->payload_len = ntohs ( sizeof ( struct udphdr ) + payload_len + udp_trailer_len);
			} else {
				sent_ip6->payload_len = ntohs (tcp_header_len + payload_len);
			}
		}	

	}
	
	// calculate new checksums
	//IP ( only IPv4)
	if ( prot3 == 4 ) {
		if ( off_ipcheck != 1 ) { 
			sent_ip->check = 0;
			sent_ip->check = ip_checksum((char *)sent_datagram, 20);
			ipcheck_wrg = 0;

		} else {
			uint16_t oldcheck = sent_ip->check;
			sent_ip->check = 0;
			uint16_t newcheck = ip_checksum((char *)sent_datagram, 20);
			uint16_t chk_diff;
			chk_diff = newcheck - oldcheck;
			if (newcheck  < oldcheck)
				chk_diff--;	// carry
			ipcheck_wrg = chk_diff;
			sent_ip->check =oldcheck;
		}
	}
	// TCP
	if ( prot == 6 ) {	
		if ( off_tcpcheck != 1 ) {
			tcp_header->tcphdr.check = 0;
			if  ( prot3 == 4 )
				tcp_header->tcphdr.check =  transport_checksum(sent_datagram +   ip_header_len , tcp_header_len + payload_len, inet_addr(local_addr), dst.sin_addr.s_addr);
  			else if  ( prot3 == 6 )
				tcp_header->tcphdr.check =  transport_checksum6(sent_datagram + ip_header_len , tcp_header_len + payload_len, sent_ip6->saddr, sent_ip6->daddr); 
			tcpcheck_wrg = 0;
		} else {
			uint16_t oldcheck = tcp_header->tcphdr.check;
			tcp_header->tcphdr.check = 0;
			uint16_t newcheck;
			if  ( prot3 == 4 )	
				newcheck = transport_checksum(sent_datagram +   ip_header_len , tcp_header_len + payload_len, inet_addr(local_addr), dst.sin_addr.s_addr);
			else if  ( prot3 == 6 )
				newcheck = transport_checksum6(sent_datagram + ip_header_len , tcp_header_len + payload_len, sent_ip6->saddr, sent_ip6->daddr); 
			uint16_t chk_diff;
			chk_diff = newcheck - oldcheck;
			if (newcheck  < oldcheck)
				chk_diff--;	// carry
			tcpcheck_wrg = chk_diff;
			tcp_header->tcphdr.check = oldcheck;
		}
	} 	
	//UDP
	else if ( prot == 17 ) {
		uint16_t oldcheck = 0;
		// store custom checksum
		if ( off_udpcheck ) 
			oldcheck = udp_header->check;
		// compute correct checksum
		udp_header->check = 0;
		uint16_t correctcheck = 0;
		uint16_t newcheck = 0;
		uint32_t newcheck_add = 0;

		int udp_len_to_check = sizeof(struct udphdr) + payload_len;
		if ( udpcheck_ippay || udpcheck_3rd )
			udp_len_to_check += udp_trailer_len;
		
		int udp_ph_len = sizeof(struct udphdr) + payload_len;
		if ( udpcheck_ippay || udpcheck_4th )
			udp_ph_len += udp_trailer_len;
		
		if  ( prot3 == 4 )	
			correctcheck = transport_checksum_custom(sent_datagram +   ip_header_len , udp_len_to_check, udp_ph_len, inet_addr(local_addr), dst.sin_addr.s_addr);
		else if  ( prot3 == 6 )
			correctcheck = transport_checksum_custom6(sent_datagram + ip_header_len , udp_len_to_check, udp_ph_len, sent_ip6->saddr, sent_ip6->daddr); 
		newcheck = correctcheck;
        // add offset to correct checksum
        if ( udpcheck_add != 0 ) {
        	newcheck_add =  (ntohs(correctcheck) + ntohs(udpcheck_add));
        	if (newcheck_add >= 0x10000)
        		newcheck_add = newcheck_add / 0x10000 + newcheck_add % 0x10000;
        	newcheck = htons(newcheck_add);
        }
        // restore custom checksum
        if ( off_udpcheck ) 
        	newcheck = oldcheck;
        // set the checksum
        udp_header->check = newcheck;
        // calculate difference between correct and written checksum
		uint16_t chk_diff;
		chk_diff = correctcheck - newcheck;
		if (correctcheck  < newcheck)
			chk_diff--;	// carry
		udpcheck_wrg = chk_diff;
		// udp_header->check = oldcheck;
	}
	// ICMP
	else if ( prot == 1 ) {
		if ( off_icmpcheck != 1 ) {
			sent_icmp->checksum = 0;
			if  ( prot3 == 4 )
				sent_icmp->checksum = ip_checksum(sent_icmp , sizeof(struct my_icmphdr) + payload_len ); //
  			else if  ( prot3 == 6 )
				sent_icmp->checksum=0; //udp_header->check = transport_checksum6(sent_datagram + ip_header_len , sizeof(struct udphdr) + payload_len , sent_ip6->saddr, sent_ip6->daddr); 		
			icmpcheck_wrg = 0;
		} else {
			uint16_t oldcheck = sent_icmp->checksum;
			sent_icmp->checksum = 0;
			uint16_t newcheck;
			if  ( prot3 == 4 )	
				newcheck = ip_checksum(sent_icmp , sizeof(struct my_icmphdr) + payload_len ); 
			else if  ( prot3 == 6 )
				newcheck=0; //transport_checksum6(sent_datagram + ip_header_len , sizeof(struct udphdr) + payload_len, sent_ip6->saddr, sent_ip6->daddr); 
			uint16_t chk_diff;
			chk_diff = newcheck - oldcheck;
			if (newcheck  < oldcheck)
				chk_diff--;	// carry
			icmpcheck_wrg = chk_diff;
			icmp_header->checksum = oldcheck;

		}
	}
	

	// drop reset if tcp
	// this is not handled correclty with JNI in Android
	char iptables_rule [100];
	//	system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP");
	//	execve("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP","","");
	char* ipt_argv[] = {NULL, "-A\0", "OUTPUT\0", "-p\0", "tcp\0", "--tcp-flags\0", "RST\0", "RST\0", "-j\0", "DROP\0", NULL};
	char* envp[] = {NULL};
	//	int h = execve("iptables", (char * const*) ipt_argv, envp);
	

	// loop for repeating
	for (int i = 0; i< repeat; i++) {

	// loop for increasing ttl
		for (ttl = first_ttl; ttl <= max_ttl; ttl=ttl+1) {
		    int probe;
	        int unreachable = 0; /* counter */
	        int gotlastaddr = 0; /* flags */
	        int got_there = 0;
	        int got_host = 0;
	        
	        path_length = ttl;
	        
	        if (got_dest == 1)
	            break;
	        
			// if it's a single probe with const ttl gets from the custom params
			if ( cst_ttl  == 1 )
				if ( custom_ip->ttl >= 1 )
					ttl = custom_ip->ttl;
				else
					ttl = 1;
			

			
			// test if to avoid
			if ( ttl == skip_ttl  ) {

				printf("%3d:  ", ttl); printf("skipped  \n");
				continue;
			}

			// loop for n probes for each ttl
	        for (probe = 0; probe < nprobes && stars_counter < stars_max; ++probe) {	
	            if (got_host == 1)
	                break;
	        
	            int read_len, read_len_r, read_len_s;

	         	int left_ms;
	            
				// set increasing ttl if not constant
				if ( cst_ttl != 1 ) {	
					if (prot3 == 4)
						sent_ip->ttl = ttl;
					if (prot3 == 6)
						sent_ip6->hop_limit = ttl;
				}
				
				// set increasing source port if choosen
				if ( increase_port == 1) {
					if ( prot == 6 )
						tcp_header->tcphdr.source = htons(20000 -1 + ttl);
					else if ( prot == 17 )
						udp_header->source = htons(20000 -1 + ttl);;
						
				}

				// calculate new ip checksum
				if ( cst_ttl == 0 ) { // only if modifications occurred to default packet			
					if ( off_ipcheck != 1 ) {	
						if (prot3 == 4 ) {
							sent_ip->check = 0;
							sent_ip->check = ip_checksum((char *)sent_datagram, 20);
						}
						// NO IPv6 Checksum
					}
				}

				// calculate new tcp udp checksum 
				if ( increase_port == 1 || 0 ) { // only if modifications occurred to default packet
					// TCP
					if ( prot == 6 ) {	
						if ( off_tcpcheck != 1 ) {
							tcp_header->tcphdr.check = 0;
							tcp_header->tcphdr.check =  transport_checksum(sent_datagram +   sizeof (struct iphdr) , tcp_header_len + payload_len /*sizeof(struct tcphdr_mss)*/, inet_addr(local_addr), dst.sin_addr.s_addr);
						}
					} 	
					//UDP
					else if ( prot == 17 ) {
						if ( off_udpcheck != 1 ) {
							udp_header->check = 0;
							udp_header->check = transport_checksum(sent_datagram +   sizeof (struct iphdr) , sizeof(struct udphdr) + payload_len, inet_addr(local_addr), dst.sin_addr.s_addr); 
						}
					}
				}

				// if it's the first probe show info about first packet sent
				if ( print_0 == 1 ) {
					if ( first_probe == 1 ) {
					    
						// show source	
						printf("  0:  ");
						if (prot3 == 4 )
							printf("%-15s  ", local_addr);	
						else if ( prot3 == 6)
							printf("%-39s  ", local_addr);	

						// leave space for times info, wayback ttl 
						if ( show_ms == 1 )
							print_last_rtt_empty();

						if ( wayback_ttl == 1 )
							print_wayback_ttl_empty();

						// print info about packet
						print_essential_pkt_info(sent_datagram +ip_header_len, payload_len, recv_only);

						// show differences with default packet
						if ( recv_only != 1 )
							if ( compare_default == 1 ) {
								// fast check if not the default packet
								//if ( memcmp (sent_datagram, default_pkt, ip_header_len + tcp_header_len + payload_len ) != 0 ) {
									//printf("[");
									compare_packets_default( sent_datagram, 0, default_pkt, 0);
									//printf("]");
								//}
							}
						first_probe = 0;
					
					
						//printf("\n");
						printf("\n");

					}
				}

				// if it's the first probe with this ttl print ttl value
				if ( probe == 0 ){
					// execpt if it's only recv
					if ( recv_only != 1 )	
						printf("%3d:  ", ttl); // flush needed fflush(stdout);
					else
						printf("   :  ");
				}

				int sent_len;
				if ( recv_only != 1 )
					sent_len = send_probe(sent_datagram, seq, ttl, 1, 0); // Send probe
				else
					sent_len = 0;

				if ( print_last_sent ) 
					last_sent_len = sent_len;

		   	    seq++;            
	            left_ms = waittime * 1000;
		            
				while ( 1 ) {
					read_len = -1;
					int which_sock = 0;

					int ip_rec_len;
					int ipp_sent_len;

					int tcp_rec_len;
					int tcp_sent_len;
					
					int pay_rec_len;
					int pay_sent_len;

		
					// wait for icmp error or reply
					memset (recv_pkt, 0, DATAGRAM_SIZE);
					read_len = wait_for_reply(rcvsock, from_lsa, to, &t2, &left_ms, &which_sock);		

					if ( which_sock == 2 ) {
					// read reply if no icmp received 
					if ( read_len != -1 )  { 

						char *ina = rz_ntoa(dst2.sin_addr);
						char *ina2 = rz_ntoa(dst.sin_addr);


					if  ( 1	) { // changed to unconditional 
                    	got_dest = 1;
						got_host = 1;
	                    answer_len = read_len;

						// print ip address
						if (prot3 == 4 ) {	
							printf("%-15s  ", ina); 
						} else  if (prot3 == 6 ) {	
							char ina[ INET6_ADDRSTRLEN];
							inet_ntop(AF_INET6, &(dst26.sin6_addr), ina, INET6_ADDRSTRLEN);
							printf("%-39s  ", ina); 
						}			

						// print round trip times rtt
						if ( show_ms == 1 )
							print_last_rtt();

						// print way back ttl				
						if ( wayback_ttl == 1 ) {
							// TTL of reeived TCP packet itself
							int icmpttl = answer_pkt[8];
							print_wayback_ttl_and_norm(icmpttl);
						}

						// TCP - UDP -- PAYLOAD	
						int tcp_rec_len;
						int tcp_sent_len;
						int payload_rec_len;
						if (prot3 == 4 ) {				           
							tcp_rec_len = read_len - 20;
							tcp_sent_len = sent_len - 20; // no ip icmp headers for both
							payload_rec_len=0;
							if ( prot == 6 ) 	
								 payload_rec_len = read_len - sizeof(struct iphdr) - answer_tcp->tcphdr.doff * 4;
							else if ( prot == 17 )
								payload_rec_len = read_len - sizeof( struct iphdr) - sizeof (struct udphdr );
							else if ( prot == 1 )
								payload_rec_len = read_len - sizeof( struct iphdr) - sizeof (struct my_icmphdr );
						} else if (prot3 == 6 ) {		
							tcp_rec_len = read_len;
							tcp_sent_len = sent_len - 40; // no ip icmp headers for both
							payload_rec_len=0;
							if ( prot == 6 ) 	
								 payload_rec_len = read_len - answer_tcp->tcphdr.doff * 4;
							else if ( prot == 17 )
								payload_rec_len = read_len - sizeof (struct udphdr );
							else if ( prot == 1 )
								payload_rec_len = read_len - sizeof (struct my_icmphdr );
						}
						
						if ( prot == 6 ) {
							printf("[TCP");
							if (prot3 == 4 ) {						
								if ( answer_pkt[33] ) {
									printf(" ");
									print_tcp_header_flags(answer_pkt + sizeof(struct iphdr));
								}

								if ( payload_rec_len != 0 )
									printf(" %d bytes", payload_rec_len);
								printf( "]  " );						
							} else 	if (prot3 == 6 ) {						
								if ( answer_pkt[13] ) {
									printf(" ");
									print_tcp_header_flags(answer_pkt);
								}
								if ( payload_rec_len != 0 )
									printf(" %d bytes", payload_rec_len);
								if ( prot3 == 6 )
									printf(" (IPv6)");
								printf( "]  " );						
							}

						}
						else if (prot == 17 ) {
							printf("[UDP");
							if ( payload_rec_len != 0 )
								printf(" %d bytes", payload_rec_len);
							if ( prot3 == 6 )
									printf(" (IPv6)");
							printf( "]  " );
						}
						else if (prot == 1 ) {
							printf("[ICMP");
							if ( payload_rec_len != 0 )
								printf(" %d bytes", payload_rec_len);
							if ( prot3 == 6 )
									printf(" (IPv6)");
							printf( "]  " );
						}

						int ip_hdr_offset = 20;
						if (prot3==6)
							ip_hdr_offset = 0;
						for (int i=0; i<4; i++) {
							saved_seq[i] = answer_pkt[ip_hdr_offset + 4 +i];
							saved_ack_seq[i] = answer_pkt[ip_hdr_offset + 8 + i];
						}
						saved_flags=answer_pkt[ip_hdr_offset + 13];

						// dest ip etc
						if ( dest_ip == 1 ) {
							int ip_offset=0;	
							if (prot3 == 4 )
								ip_offset = 0;						
							else if (prot3 == 6 )
								ip_offset = 0;
	            			compare_ip_packets(sent_datagram, 0, answer_pkt, 0, tcp_rec_len, mod_pkt, mod_pkt_msk, sent_ip->ttl);
						}

						// dest tcp etc
						if (prot == 6 ) {
							int tcp_offset=0;	
							if (prot3 == 4 )
								tcp_offset = 20;						
							else if (prot3 == 6 )
								tcp_offset = 0;
							if ( dest_tcp == 1 )
								compare_tcp_packets(sent_datagram, ip_header_len, answer_pkt, tcp_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk);
							if ( dest_ecn == 1 )
								print_tcp_ecn(answer_pkt + tcp_offset );
							if ( dest_ack == 1 )
								print_tcp_ack(answer_pkt + tcp_offset );
							if ( dest_opt == 1)
								compare_tcp_options(sent_datagram, ip_header_len, answer_pkt, tcp_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk, show_all_opt);

							// print payload as required
							int pay_offset=0;	
							if (prot3 == 4 )
								pay_offset = 20;						
							else if (prot3 == 6 )
								pay_offset = 0;
							if ( dest_pay_1 == 1 )
								print_payload(sent_datagram, 20, answer_pkt, pay_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk, 1, 0, 0, 0);	
							if ( dest_pay_printable == 1 )
								print_payload(sent_datagram, 20, answer_pkt, pay_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk, 0, 1, 0, 0);
							if ( dest_pay == 1 )
								print_payload(sent_datagram, 20, answer_pkt, pay_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk, 0, 0, 1, 0);
							if ( dest_pay_choice == 1 )
								print_payload(sent_datagram, 20, answer_pkt, pay_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk, 0, 0, 0, 1);	

						}		
						else if (prot == 17) {
							int udp_offset=0;	
							if (prot3 == 4 )
								udp_offset = 20;						
							else if (prot3 == 6 )
								udp_offset = 0;
							if ( dest_udp == 1)
								compare_udp_packets(sent_datagram, ip_header_len, answer_pkt, udp_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk);
						}
						break;					
					}	
				}	

				} // end if (which_sock == 2)	

                // No packet received
            	if (read_len == -1) {
                	printf("* "); 
                	stars_counter++; // Increase the counter of stars
					break;
            	}

            	if ( (read_len>0) && (debug_random_mod) ) {
            		int r = rand_long_int() % read_len;
            		recv_pkt[r]=recv_pkt[r]*2+1;
            	}
			
                // Check packets
                int icmp_code;
                icmp_code = packet_ok(read_len, from_lsa, to, seq);

				if (icmp_code > 0) {
					got_host = 1;
					got_dest = 1; 
					got_there = 1;
				}

				if (icmp_code == 2 ) {
					break;
				}

                // quoted tcp len
				if ( prot3 == 4 ) {
				        tcp_rec_len;
				        // RZ it was   tcp_rec_len = read_len - 20 - 8 - (quoted_ip->ihl << 2);
					tcp_rec_len = read_len - 20 - 8 - 20 ;	// to be corrected !!!
					tcp_sent_len = sent_len - 20 ; // RZ it was   - 20 - 8 - (quoted_ip->ihl << 2);
		                } else if ( prot3 == 6 ) {
					quoted_tcp_offset = 48;
					tcp_rec_len = read_len -8 -40;
					tcp_sent_len = sent_len - ip_header_len ;
				}

				// payload
				int payload_rec_len=0;
				if ( prot == 6 ) 	
					 payload_rec_len = read_len - sizeof(struct iphdr) - rec_tcp->doff * 4;
				else if ( prot == 17 )
					payload_rec_len = read_len - sizeof( struct iphdr) - sizeof (struct udphdr );
	 
	 			// print source address of icmp msg
				char* addr;
				addr = rz_ntoa(dst2.sin_addr);
				if (!gotlastaddr || ( memcmp(lastaddrseen, addr, strlen(addr) ) != 0) ) {
					// print node ip
					if (prot3 == 4 ) {	
						char* addr;
						addr = rz_ntoa(dst2.sin_addr);
						printf("%-15s  ", addr);
					} else  if (prot3 == 6 ) {	
						char ina[ INET6_ADDRSTRLEN];
						inet_ntop(AF_INET6, &(dst26.sin6_addr), ina, INET6_ADDRSTRLEN);
						printf("%-39s  ", ina); 
					}


	                memcpy(lastaddrseen , addr, strlen(addr));  // to be done: HANDLE this later !!!
	                gotlastaddr = 1;
	                got_host = 1;
				}

				// print round trip times rtt
				if ( show_ms == 1 )
					print_last_rtt();

				// print way back ttl-
				if ( wayback_ttl == 1 ) {
					int icmpttl = recv_pkt[8];
					print_wayback_ttl_and_norm( icmpttl);
				}
			

				// print quoted packet length
				int len1= tcp_rec_len, len2=tcp_sent_len;
				if ( tcp_rec_len > tcp_sent_len ) {
					len1=len2;			
				}
				printf("[");
				printf("%d/%d", len1, len2 );
				// print additional info about ICMP MSG UNUSED BYTES, LENGTH AND MULTIPART
				if ( !no_icmp_info ) {
					if ( icmp_4884_length != 0 )
							printf (" !ICMP::Length(%d)", icmp_4884_length);
					if ( icmp_unused != 0 )
							printf (" !ICMP::Unused(%08x)", icmp_unused);
					if ( icmp_is_multipart != 0 )
							printf (" !ICMP::Multipart(%d)", icmp_multipart_start_at);		
				}
				printf("]  ");


                // if (1) {	// changed to not conditional

				stars_counter = 0; // Init the counter because we found an host


				// quoted length			
				if ( show_quoted_len == 1 ) {
					int quo_len = read_len - 20 - 8 -20;	// read_len - ip length - icmp length - ip length
					if ( quo_len > tcp_sent_len )
						printf("(%d out of %d bytes quoted)  ", tcp_sent_len, tcp_sent_len ); 
					else
						printf("(%d out of %d bytes quoted)  ", quo_len, tcp_sent_len ); 			
				}
				
				// IP
				if ( prot3 == 4 ) {
// 					compare_ip_packets(sent_datagram, 0, recv_pkt,  quoted_ip_offset, (sent_ip->ihl >= quoted_ip->ihl ? quoted_ip->ihl << 2 : sent_ip->ihl << 2), mod_pkt, mod_pkt_msk, ttl);
					compare_ip_packets(sent_datagram, 0, recv_pkt,  28, 20, mod_pkt, mod_pkt_msk, ttl);
				}
				else if (prot3 == 6 ) {

					compare_ip6_packets(sent_datagram, 0, recv_pkt, 8, 40 , mod_pkt, mod_pkt_msk, ttl);
				}

				// TCP - UDP
				if (prot == 6 ) {
					compare_tcp_packets(sent_datagram, ip_header_len, recv_pkt, quoted_tcp_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk);
					compare_tcp_options(sent_datagram, ip_header_len, recv_pkt, quoted_tcp_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk, 0);
				}
				else if (prot == 17) 
					compare_udp_packets(sent_datagram, ip_header_len, recv_pkt, quoted_tcp_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk);

				// for every prot
				if (!hide_pay)
				compare_payload(sent_datagram, ip_header_len, recv_pkt, quoted_tcp_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk);

				// PAYLOAD
				// if ( payload_len >= 0 )
				if ( payload_rec_len >= payload_len ) {
					;//printf("FULL PAYLOAD %d %d ", payload_rec_len,  payload_len );
					if ( strncmp( & sent_datagram[ 40], & recv_pkt [quoted_tcp_offset+20], 400 ) != 0 )
						;//printf ("\n%400s \n %400s \n", & sent_datagram[ 40], & recv_pkt [quoted_tcp_offset+20]);
				}
	                    // End the loop for this ttl
	                    if (icmp_code == -1)
	                        break;
	                    if (icmp_code == 1)
	                        break;
	                // }
	                
	            }

	        }
	        
	        printf(" \n");
	        if (got_there || (unreachable > 0 && unreachable >= nprobes - 1))
	            break;
	        
	        // stopping trace
	        if (stars_counter == stars_max)
	            break;
	   
			// if ttl is const, it breaks the ttl increasing for
			if ( cst_ttl == 1 )
				break;
		    
		} // end of ttl for

    } // end of repeat for

	// other output options

	// print last sent packet
	if ( print_last_sent ) {
		printf( "Last Packet Sent: 0x");
		int sent_len = last_sent_len;
		print_pkt_hex (sent_datagram, sent_len);
		printf ( "\n" );
	} 
		
	return 0;
}


void internal_common_tracebox_main(int argc, char *argv[], char * dest_addr)
{
	int tbs = 1;
	int args_split[30];
	args_split[0]= 1;
	// test how many tracebox to do

	if (argc > 2) {
		for (int i = 2; i < argc; i++ ) {
			// printf("internal tb main args ");				
			// printf(argv[i]);
			// printf("\n");
			if ( strncmp (argv[i], "--", 2 ) == 0 ) {
				args_split[tbs] = i;
				tbs++;	
				
			}
		}
		
	}

	args_split[tbs] = argc;
/*	
	for ( int i = 0; i < tbs; i++ ) {
		for ( int j =  args_split[i]; j < args_split[i+1]; j++ ) {
			printf ("%s ", argv[j]);
		}
		printf ("\n");
	}
*/ 
	unsigned char sent_copy[DATAGRAM_SIZE];	
	int payload_len_copy=0, tcp_header_len_copy=20;
	int prot_copy=6;
	memset(sent_copy, 0, DATAGRAM_SIZE);
	for ( int i = 0; i < tbs; i++ ) {
		if ( (dropped_rst==0) && (off_drop_rst==0) && (prot==6)) {
			//popen("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP", "w");	
			//dropped_rst = 1;
			// move this outside of tracemore, not handled correctly by JNI on Android
		}
			
		reset_single_tb_params();
		parse_params( args_split[i+1] - args_split[i], * (& argv) + args_split[i] );

		if ( nr_tb_hide )
			printf("STARTDEBUGINFO\n");
		common_tracebox_main(dest_addr);
		if ( nr_tb_hide )
			printf("ENDDEBUGINFO\n");
		//sleep(3);	
		if ( nr_tb_packet )  {
			memcpy(sent_copy, sent_datagram, DATAGRAM_SIZE);
			prot_copy=prot;
			payload_len_copy=payload_len;
			tcp_header_len_copy=tcp_header_len;
		}

	}
	// restore intended nr tb packet
	prot=prot_copy;
	memcpy(sent_datagram, sent_copy, DATAGRAM_SIZE);
	tcp_header_len=tcp_header_len_copy;
	payload_len=payload_len_copy;

}	


int hostname_to_ip(char * hostname , char* ip, int prot3) {
#ifdef _NO_GETADDRINFO
return 1;
#endif
#ifndef _NO_GETADDRINFO
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s, j;
	size_t len;
	ssize_t nread;

	memset(&hints, 0, sizeof(struct addrinfo));
	if ( prot3 == 4 )
		hints.ai_family = AF_INET;
	else 	if ( prot3 == 6 )
		hints.ai_family = AF_INET6;
	hints.ai_socktype = 0; 
	hints.ai_flags = 0;
	hints.ai_protocol = 0;          

	s = getaddrinfo(hostname, 0, &hints, &result);
	if (s != 0) {
		return 1;
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (prot3==4) {
	  		struct sockaddr_in * h = (struct sockaddr_in *) rp->ai_addr;
			inet_ntop(AF_INET, &(h->sin_addr), ip, INET_ADDRSTRLEN);
			//printf ("%s\n", ip);
			freeaddrinfo(result);
			return 0;
		}
		else if (prot3==6) {
	  		struct sockaddr_in6  * h = (struct sockaddr_in6 *) rp->ai_addr;
			inet_ntop(AF_INET6, &(h->sin6_addr), ip, INET6_ADDRSTRLEN);
			//printf ("%s\n", ip);
			freeaddrinfo(result);
			return 0;
		}		
	}

	return 1;
#endif	

}

void udp_echo( void* socket_desc) {
	int nr_sndsock = *(int*)socket_desc;	
	struct timeval tv;
	tv.tv_sec = 1; 			// 1 sec to iterate
	tv.tv_usec = 0; 
	int s;	
	s  = setsockopt(nr_sndsock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));	
	// printf("set to udp %d\n", s);
	// get answer
	memset(nr_answer_pkt,0,DATAGRAM_SIZE);
	struct sockaddr_in d;
	int ds=sizeof(d);
	int recv_len = -1;
	char answer[2] = {0xbb, 0xbb};
	int iterations = 0;
	do {	
		iterations++;
		recv_len = recvfrom(nr_sndsock , nr_answer_pkt , DATAGRAM_SIZE, 0,  ( struct sockaddr *) &d , &ds ) ;
		//printf("recv udp %d\n", recv_len);
		//print_pkt(nr_answer_pkt, recv_len);
		if ( recv_len > 0 )
			sendto(nr_sndsock, answer, 2, 0,  (const struct sockaddr *) &dst , sizeof(struct sockaddr)  );
		if ( recv_len == 0 )
			sendto(nr_sndsock, answer, 0, 0,  (const struct sockaddr *) &dst , sizeof(struct sockaddr)  );
		nr_answer_len=recv_len;
	} while ( ( nr_answer_len <= 0 ) && (!nr_tracebox_back_ended) && (iterations < NR_TRACEBOX_BACK_TIMEOUT) );
}


int SE_tracebox(){
	return 0;
}

int se_udpo_tracebox() {
	
	// ifadrr
	get_ifaddrs();

	int dports_number = 11;
	int se_dports[11] = {34781, 34782, 34783, 34784, 34785, 34786, 34787, 34788, 34789, 34790, 34791 };
	int udpo_outcomes[11] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	
	// create non raw socket
	se_prot3= prot3;
	int af = 0;			

	// family 
	if ( se_prot3 == 4 )
		af = AF_INET;
	else if ( prot3 == 6 )
		af = AF_INET6;

	int se_udpo_sndsock[dports_number];
	for (int i=0; i<dports_number; i++) {
		se_udpo_sndsock[i] = socket(af, SOCK_DGRAM, 0);
	}
	
	struct sockaddr_in server4[dports_number];
	struct sockaddr_in6 server6[dports_number];
			

	// dest and port
	for (int i=0; i<dports_number; i++) {
		int dport= se_dports[i];
		if ( se_prot3 == 4 ) {
			server4[i].sin_addr.s_addr = inet_addr(dest_addr);
		    	server4[i].sin_family = af;
		    	server4[i].sin_port = htons( dport );
		} else if ( se_prot3 == 6 ) {
			inet_pton(AF_INET6, dest_addr, (void *)&server6[i].sin6_addr.s6_addr);
			server6[i].sin6_flowinfo = 0;
		    	server6[i].sin6_family = af;
		    	server6[i].sin6_port = htons( dport );
			server6[i].sin6_scope_id = 0;
		}
 	}


	
	// set options
	int s=-1;
	int val=0;
	int on=1;
	int off=1;
	int size = sizeof(on);
	int val_size=sizeof(val);

	unsigned char packet[1500];
	unsigned char answer_packet[1500];
	memset(packet, 0, 1500);
	memset(answer_packet, 0, 1500);

	payload_len=20;

	struct sockaddr_in dst[dports_number];
	int dstlen;

	struct sockaddr_in src4;
	memset(&src4, 0, sizeof(src4));
	struct sockaddr_in6 src6;
	memset(&src6, 0, sizeof(src6));



	if ( prot3 == 4 )
		af = AF_INET;
	else if ( prot3 == 6 )
		af = AF_INET6;
	for (int i=0; i<dports_number; i++) {
		int r = rand_long_int() % 0xfc00;
		if (af == AF_INET) {
			for ( int j = r; j<0xffff; j++ ) {
				src4.sin_addr.s_addr = inet_addr(local_addr);
			    	src4.sin_family = af;	    	
			    	src4.sin_port = htons( i );
				if( bind(se_udpo_sndsock[i],(struct sockaddr *) &src4 , sizeof(src4) ) <0 ) {
					//printf("bind failed %d\n", j);
				}
				else {
					//printf("bind done %04x\n", j);
				}
			}
		}
		else {
			for ( int j = r; j<0xffff; j++ ) {
				inet_pton(AF_INET6, local_addr, (void *) &src6.sin6_addr.s6_addr);
				src6.sin6_family = af;
				src6.sin6_port = htons( i );
				if( bind(se_udpo_sndsock[i],(struct sockaddr_in6 *) &src6 , sizeof(src6) ) <0 ) {
					//printf("bind failed %d\n", j);
				}
				else {
					//printf("bind done %04x\n", j);
				}	
			}
		}
	}

	for (int j=0; j<3; j++) {
		for (int i=0; i<dports_number; i++) {
			dst[i].sin_family = af;
			dst[i].sin_addr.s_addr=inet_addr(dest_addr);
			dst[i].sin_port = htons(se_dports[i]);
			if (af == AF_INET ) 
				for (int k=0; k<1; k++) {
					sendto(se_udpo_sndsock[i], packet, payload_len, 0,  (const struct sockaddr *) &server4[i] , sizeof(struct sockaddr)  );
				}
			else 
				for (int k=0; k<1; k++) {
					sendto(se_udpo_sndsock[i], packet, payload_len, 0,  (const struct sockaddr_in6 *) &server6[i] , sizeof(struct sockaddr_in6)  );
				}	
			usleep(10000);
		}
		usleep(100000);
	}


	sleep(SE_UDPO_TIMEOUT);

/*
	struct timeval tv;
	tv.tv_sec = 3;
	tv.tv_usec = 0; 
	for (int i=0; i<dports_number; i++) {	
		s  = setsockopt(se_udpo_sndsock[i], SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
	}
*/
	
	for (int i=0; i<dports_number; i++) {	
		int recv_len = recvfrom(se_udpo_sndsock[i], answer_packet, 1,  MSG_DONTWAIT, ( struct sockaddr *) &dst[i] , &dstlen ) ;
		// printf("recv_len %d\n", recv_len);
		if (recv_len==-1)
			udpo_outcomes[i]=0;
		else
			udpo_outcomes[i]=1;
		
	}
	
	for (int i=0; i<dports_number; i++) {	
		// printf("%d\n", udpo_outcomes[i]);
	}


	const char* se_udpo_packets[15] = {	"UDP (Correct CS)",
						"UDP (Zero CS)",
						"UDP (Bad CS)",
						"UDPO (Correct CS)",
						"UDPO (Zero Padding)",
						"UDPO (3rd CS)",
						"UDPO (4th CS)",
						"UDPO (IP Payload CS)",
						"UDPO (Zero CS)",
						"UDPO (Bad CS)",
						"UDPO (w/ OCS)"
	};


	// print results
	printf("traceboxing from  %s  to  %s\n",  local_addr, dest_addr);
	// show source	
	/**/
	printf("  0:  ");
	if (prot3 == 4 )
		printf("%-15s  ", local_addr);	
	else if ( prot3 == 6)
		printf("%-39s  ", local_addr);	
		// print info about packet
	printf("[UDP]  ");
	printf("\n");
	/**/
	for (int i=0; i<dports_number; i++) {	

		// printf(" 64:  ");
		printf("   :  ");

		if (udpo_outcomes[i]) {
			if (prot3 == 4 )
				printf("%-15s  ", dest_addr);	
				// printf("OK  ");
			else if ( prot3 == 6)
				printf("%-39s  ", dest_addr);
		} else {
			if (prot3 == 4 )
				printf("%-15s  ", "*");	
			else if ( prot3 == 6)
				printf("%-39s  ", "*");
		}
		printf("[%s]",se_udpo_packets[i]);	

		printf("\n");
	}

	//printf("SE_UDPO end\n");


}

int NR_tracebox(int argc, char *argv[]) {
		
	// print debug line
	printf ("STARTDEBUGINFO\n");	
	
	// set some tb options
	hide_opt_changed=1;

	get_ifaddrs();

	// create non raw socket
	int af = 0;		// family 
	int s=-1; 		// result of setsockopt
	if ( prot3 == 4 )
		af = AF_INET;
	else if ( prot3 == 6 )
		af = AF_INET6;
	
	//
	nr_prot4 = prot;
	int sport = 20000;
	int dport = nr_dest;
	int tb_serv_port = 8000;


	// dest port
	nr_dest_got = dport;

	if ( nr_prot4 == 6 )
		nr_sndsock = socket(af, SOCK_STREAM, 0);
	else if ( nr_prot4 == 17 )
		nr_sndsock = socket(af, SOCK_DGRAM, 0);

	// set options
	int on = 1;
	int off = 0;
	int got= -1;
	int size =  sizeof(got);
	//s = setsockopt(nr_sndsock, IPPROTO_TCP, TCP_CORK, &off,sizeof(off));
	s = setsockopt(nr_sndsock, IPPROTO_TCP, TCP_NODELAY, &on,sizeof(on));		
//	s = getsockopt(nr_sndsock, IPPROTO_TCP, TCP_NODELAY,  (char*)&got,&size);	
	printf ("set nodelay %d %d\n" , s, got);
//	s = setsockopt(nr_sndsock, SOL_SOCKET, SO_KEEPALIVE, &on,sizeof(on));	
	printf ("set keepalive %d\n" , s);
	int alive = 10;
//	s = setsockopt(nr_sndsock, SOL_SOCKET, SO_KEEPALIVE, &alive,sizeof(alive));	
	printf ("set keepidle %d\n" , s);
	s = setsockopt(nr_sndsock, IPPROTO_TCP, TCP_QUICKACK, &off,sizeof(off));
	printf ("set quickack %d\n", s);
	int syns = 3;
	if ( (nr_back==1) && (nr_tcp_pay==0) ) {
		syns = 3;
	}	
	if ( nr_syncnt > 0 )
		syns = nr_syncnt;

	s = setsockopt(nr_sndsock, IPPROTO_TCP, TCP_SYNCNT, &syns,size);
	s = getsockopt(nr_sndsock, IPPROTO_TCP, TCP_SYNCNT, &syns,&size);		
	printf ("set syntcount %d %d\n" , s, syns);
//	s = setsockopt(nr_sndsock, SOL_SOCKET, TCP_MD5SIG, &on,sizeof(off));	
//	printf ("set md5 %d\n" , s);
	
	char optval[10] ="\0";
	strcpy(optval, "reno");
	int optlen = strlen(optval);
	//s = setsockopt(nr_sndsock, IPPROTO_TCP, TCP_CONGESTION, optval, optlen);
	//printf ("set tcp cong %d\n" , s);	

	// MSS
	int mss_value;
	if ( prot3 == 4 ) 
		mss_value = 1460;
	else  if ( prot3 == 6 ) 
		mss_value = 1460;
	int mss_value_len = sizeof(mss_value);
	if ( mss_value != nr_tcp_mss ) {
		s = setsockopt(nr_sndsock, IPPROTO_TCP, TCP_MAXSEG, &nr_tcp_mss, sizeof(nr_tcp_mss));
		printf("mss %d %d\n", s, mss_value);
	}
	

	int rcvbuf;
	int clamp;
	if ( nr_tcp_ws == 0 ) {
		rcvbuf = 0x1000;
		nr_tcp_window_reliable = 0;
	}
	else if ( nr_tcp_ws == 1 ) {
		rcvbuf = 0x10000;
		nr_tcp_window_reliable = 0;
	}
	else if ( nr_tcp_ws == 2 ) {
		rcvbuf = 0x100000;
		nr_tcp_window_reliable = 0;
	}
	else 
		rcvbuf = -1;
	printf ("nr_tcp_window_reliable  %d\n", nr_tcp_window_reliable );

	// nr_tcp_rcvbuf overwrites then disable WS
	if ( nr_tcp_rcvbuf != -1 ) {
		rcvbuf = nr_tcp_rcvbuf;
		nr_tcp_ws_reliable = 0;		
	}
	if ( rcvbuf != -1 ) {
		s = setsockopt(nr_sndsock, SOL_SOCKET, SO_RCVBUF, (char *)& rcvbuf, sizeof(rcvbuf));
	} 
	size = sizeof(rcvbuf);
	s = getsockopt(nr_sndsock, SOL_SOCKET, SO_RCVBUF, (char *)& rcvbuf, &size);
	printf ("set rcvbuf %d\t%04x\n" , s, rcvbuf);

	clamp = 0x7210;
	clamp = 0x2;
	clamp = nr_tcp_rcvbuf / 2;
	size = sizeof(clamp);
	//s = setsockopt(nr_sndsock, SOL_SOCKET, TCP_WINDOW_CLAMP, (char *)& clamp, sizeof(clamp));
	s = getsockopt(nr_sndsock, SOL_SOCKET, TCP_WINDOW_CLAMP, &clamp, &size);
	printf ("set clamp %d\t%04x\n" , s,  clamp	);
	clamp = nr_tcp_rcvbuf;
//	setsockopt(nr_sndsock, SOL_SOCKET, TCP_WINDOW_CLAMP, (char *)& clamp, sizeof(clamp));
//	s = getsockopt(nr_sndsock, SOL_SOCKET, TCP_WINDOW_CLAMP, &clamp, &size);
	printf ("set clamp %d\t%04x\n" , s,  clamp	);
	clamp = nr_tcp_rcvbuf * 2;
//	setsockopt(nr_sndsock, SOL_SOCKET, TCP_WINDOW_CLAMP, (char *)& clamp, sizeof(clamp));
//	s = getsockopt(nr_sndsock, SOL_SOCKET, TCP_WINDOW_CLAMP, &clamp, &size);
	printf ("set clamp %d\t%04x\n" , s,  clamp	);

	// oobinline
	s = setsockopt(nr_sndsock, SOL_SOCKET, SO_OOBINLINE, &on, sizeof on);

	#ifdef TCP_MD5SIG
	if ( nr_tcp_md5 ) {
	//printf("md5 %d\n", TCP_MD5SIG_MAXKEYLEN);
		struct tcp_md5sig md5;
		struct sockaddr_in md5_server4;
		memset((char *) &md5_server4, 0, sizeof(md5_server4));
		md5_server4.sin_addr.s_addr = inet_addr(dest_addr);
		md5_server4.sin_family = af;
		md5_server4.sin_port = htons( dport );
	    	//md5_server4.sin6_family = AF_INET;	
	    	// inet_pton(AF_INET6, s6ip, &serv_addr.sin6_addr)
	    	// serv_addr.sin6_port = htons(atoi(sport));
		md5_server4.sin_addr.s_addr = inet_addr(dest_addr);
		memcpy(&md5.tcpm_addr, &md5_server4, sizeof(md5_server4));
		char * key = "AAAA";
	    	strcpy(md5.tcpm_key, key);
	    	md5.tcpm_keylen = strlen(key);
	   	s = setsockopt(nr_sndsock, IPPROTO_TCP, TCP_MD5SIG, &md5, sizeof(md5));
		printf ("set md5 %d\t%04x\n" , s);
	}
	#endif
	
	// IP 
	// DF
	if ( nr_df == 0 ) {
		int val = IP_PMTUDISC_DONT;
		int s = setsockopt(nr_sndsock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
		if (s != -1)
			nr_df_got = 0;
					
	} else
		nr_df_got = 1;	

	// MF 
	// later, after sending packet

	// TOS
	if ( nr_tos != 0 ) {
		int val = nr_tos;
		setsockopt(nr_sndsock, IPPROTO_IP,  IP_TOS , &val, sizeof(val));
		getsockopt(nr_sndsock, IPPROTO_IP,  IP_TOS , &val, sizeof(val));
		printf ("set TOS %d\n" , val);
		nr_tos_got = val;
	}	

	// TTL
	if ( 1 ) {
		int val;
		if ( nr_ttl != -1 ) 
			val = nr_ttl;
		else 
			val = 0x20;
		setsockopt(nr_sndsock, IPPROTO_IP,  IP_TTL , &val, sizeof(val));
		getsockopt(nr_sndsock, IPPROTO_IP,  IP_TTL , &val, sizeof(val));
		printf ("set TTL %d\n" , val);
		nr_ttl_got = val;
	}

	// IPv6
	// TCLASS
	if ( nr_tc != 0 ) {
		int val = nr_tc;
		setsockopt(nr_sndsock, IPPROTO_IPV6,  IPV6_TCLASS , &val, sizeof(val));
		getsockopt(nr_sndsock, IPPROTO_IPV6,  IPV6_TCLASS , &val, sizeof(val));
		printf ("set tclass %d\n" , val);
		nr_tc_got = val;
	}	
	
	// HOP LIMIT
	if ( 1 ) {
		int val ;
		int val_size;
		if ( nr_hl != -1 ) 
			val = nr_hl;
		else 
			val = 0x20;
		int s;
		s = setsockopt(nr_sndsock, IPPROTO_IPV6,  IPV6_UNICAST_HOPS , &val, sizeof(val));
		printf ("set hoplimit %d %d\n" , s, val);
		s = getsockopt(nr_sndsock, IPPROTO_IPV6,  IPV6_UNICAST_HOPS , &val, &val_size);
		printf ("get hoplimit %d %d\n" , s, val);
		nr_hl_got = val;
	}	


	// connect to the server
	int tb_serv_sock = socket(af, SOCK_STREAM, 0);
	if (!se)  {
		// set options
		{
		int on = 1;
		setsockopt(tb_serv_sock, IPPROTO_TCP, TCP_NODELAY, &on,sizeof(on));		
		setsockopt(tb_serv_sock, IPPROTO_TCP, TCP_QUICKACK, &on,sizeof(on));		
		}
		struct sockaddr_in tb_serv4;
		struct sockaddr_in6 tb_serv6;
		struct sockaddr_in tb_client4;
		struct sockaddr_in6 tb_client6;
		if ( af == AF_INET ) {
			tb_client4.sin_addr.s_addr = inet_addr(local_addr);
		    	tb_client4.sin_family = af;
		    	tb_client4.sin_port = htons( 0 );
			if( bind(tb_serv_sock,(struct sockaddr *)&tb_client4 , sizeof(tb_client4)) < 0  )
				printf("bind server failed!\n");
			else
				printf("bind server done\n");
			tb_serv4.sin_addr.s_addr = inet_addr(tb_serv_addr);
		    	tb_serv4.sin_family = AF_INET;
		    	tb_serv4.sin_port = htons( tb_serv_port );
			if (connect(tb_serv_sock , (struct sockaddr *)&tb_serv4 , sizeof(tb_serv4)) < 0) {
	//			printf("connect to server %s %d failed\n", tb_serv_addr, tb_serv_port);
				printf("connect to server failed\n");
			} else {
				printf("connected to server \n");
			}

		} else 	if ( af == AF_INET6 ) {
			inet_pton(AF_INET6, local_addr, (void *)&tb_client6.sin6_addr.s6_addr);
			tb_client6.sin6_flowinfo = 0;
		    	tb_client6.sin6_family = af;
		    	tb_client6.sin6_port = htons( 0 );
			tb_client6.sin6_scope_id = 0;
	//		client6.sin6_addr = in6addr_any;
			if( bind(tb_serv_sock,(struct sockaddr *)&tb_client6 , sizeof(tb_client6))  < 0) 
				printf("bind server failed\n");
			else
				printf("bind server done\n");
			inet_pton(AF_INET6, tb_serv_addr6, (void *)&tb_serv6.sin6_addr.s6_addr);
			tb_serv6.sin6_flowinfo = 0;
		    	tb_serv6.sin6_family = af;
		    	tb_serv6.sin6_port = htons( tb_serv_port );
			tb_serv6.sin6_scope_id = 0;
			//tb_serv6.sin6_addr = in6addr_any;
			if (connect(tb_serv_sock , (struct sockaddr *)&tb_serv6 , sizeof(tb_serv6)) < 0) {
				// printf("connect to server 6 %s  %d failed\n", tb_serv_addr6, tb_serv_port);
				printf("connect to server 6 failed\n");
			} else {
				printf("connected to server 6 \n");
			}
		}
		// send server instructions
		char message[2000] = "Packet ";
		// first line of msg
		if ( nr_prot4 == 6 ) {
			if (nr_tcp_pay == 1)
				strcat (message,"TCPPAY");
			else
				strcat (message,"TCPSYN");
			if ( nr_back == 1 ) {
				strcat (message,"\nBack: ");
				if ( !nr_back_icmp ) {
					if (nr_tcp_pay == 1) {
						strcat (message,"BACKTCPPAY");
						if (nr_forward_sack == 1)
							strcat (message,"BACKTCPFORWARDSACK");
					} else
						strcat (message, "BACKTCPSYN");	
				} else
					strcat (message, "BACKICMP");	

			}

		}
		else if ( nr_prot4 == 17 ) {
			strcpy (message,"UDP");
			if ( nr_back == 1 ) {
					strcat (message,"\nBack: ");
				if ( !nr_back_icmp ) {
					strcat (message, "BACKUDP");
				} else
					strcat (message, "BACKICMP");				
			}
		}

		// add PORT to msg
		if ( 1 ) {
			char port_string[10] = "";
			sprintf(port_string, "%d", nr_dest);
			strcat (message, "\nPort: ");
			strcat (message, port_string );		
		}
		

		// add ACK options to msg
		if ( nr_ack_opt == 1 ) {
			strcat (message, "\nAck-Options: ");
			strcat (message, nr_ack_options);
		}

		// add BACK options to msg
		if ( nr_back_opt == 1 ) {
			strcat (message, "\nBack-Options: ");
			//strcat (message, "\"");
			strcat (message, nr_back_options);
			//strcat (message, "\"");
		}

		// add SERVER TIMEOUT options to msg
		if ( nr_serv_to == 1 ) {
			char sto_string[10] = "";
			sprintf(sto_string, "%d", serv_to);
			strcat (message, "\nServer-Timeout: ");
			strcat (message, sto_string );		
		}
		
		// add CLIENT80 options to msg
		if ( nr_client80 ) {
			strcat (message, "\nClient80: ");
			strcat (message, client80_addr );		
		}
		// add /n to msg
		strcat (message, "\n\n");

		// printf("message \n%s\n", message);
		write(tb_serv_sock , message , strlen(message));
		// wait for ok
		struct timeval tv1;
		tv1.tv_sec = 5; 
		tv1.tv_usec = 0; 
		s  = setsockopt(tb_serv_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv1,sizeof(struct timeval));	
		char tb_serv_answer[10];
		memset(tb_serv_answer,0,10);
		int tb_serv_ok = recv(tb_serv_sock , tb_serv_answer , 2 , 0);
		if ( strncmp(tb_serv_answer, "OK",2) != 0 )
			return;
		else
			printf("answer %d %s\n", tb_serv_ok , tb_serv_answer);


	} // if !se

	// send syn packet
	// correct dest_addr if NR with server
	if (!se ) {
		sleep(1);
		if (prot3 == 4  )
			strcpy(dest_addr, tb_serv_addr);
		else if (prot3==6)
			strcpy(dest_addr, tb_serv_addr6);
	} // if !se

	// syn 
	struct sockaddr_in server4;
	struct sockaddr_in6 server6;
	struct sockaddr_in client4;
	struct sockaddr_in6 client6;
	struct timeval tv_c;
	tv_c.tv_sec = 10; 		// increase timeout
	tv_c.tv_usec = 0; 
	s  = setsockopt(nr_sndsock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv_c,sizeof(struct timeval));	


	// needed to keep port
	#ifdef SO_REUSEPOR
	{
	if ( nr_keep_port )
		s  = setsockopt(nr_sndsock, SOL_SOCKET, SO_REUSEPORT, &(int){ 1 }, sizeof(int));
	int val=0, val_size=sizeof(val);
	printf ("set reuseport %d\n" , s);
	s = getsockopt(nr_sndsock, SOL_SOCKET, SO_REUSEPORT, &val, &val_size);
	printf ("get reuseport %d %d\n" , s, val);
	}
	#endif

	#ifdef SO_REUSEADDR
	{
	if ( nr_keep_port )
		s  = setsockopt(nr_sndsock, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
	int val=0, val_size=sizeof(val);
	printf ("set reuseaddr %d\n" , s);
	s = getsockopt(nr_sndsock, SOL_SOCKET, SO_REUSEADDR, &val, &val_size);
	printf ("get reuseaddr %d %d\n" , s, val);
	}
	#endif

	struct tcp_info tcp_info;
	int tcp_info_length = sizeof(tcp_info);
/* 
	// retrieve tcp info first time
	#ifdef SOL_TCP
	if ( getsockopt( nr_sndsock, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_length ) == 0 ) {
		printf("	tcpi_state %u     tcpi_ca_state %u     tcpi_retransmits %u     tcpi_probes %u     tcpi_backoff %u     tcpi_options %u     tcpi_snd_wscale %u     tcpi_rcv_wscale %u    	tcpi_rto %u     tcpi_ato %u     tcpi_snd_mss %u     tcpi_rcv_mss %u    	tcpi_unacked %u     tcpi_sacked %u     tcpi_lost %u     tcpi_retrans %u     tcpi_fackets %u     tcpi_last_data_sent %u     tcpi_last_ack_sent %u    tcpi_last_data_recv %u     tcpi_last_ack_recv %u     tcpi_pmtu %u     tcpi_rcv_ssthresh 0x%x     	tcpi_rtt %u     tcpi_rttvar %u    tcpi_snd_ssthresh %u     tcpi_snd_cwnd %u    	tcpi_advmss %u    tcpi_reordering %u    \n",

		tcp_info.tcpi_state, tcp_info.tcpi_ca_state, tcp_info.tcpi_retransmits, tcp_info.tcpi_probes, tcp_info.tcpi_backoff, tcp_info.tcpi_options, tcp_info.tcpi_snd_wscale, tcp_info.tcpi_rcv_wscale,	tcp_info.tcpi_rto, tcp_info.tcpi_ato,
		tcp_info.tcpi_snd_mss,	tcp_info.tcpi_rcv_mss,	tcp_info.tcpi_unacked, tcp_info.tcpi_sacked, tcp_info.tcpi_lost, tcp_info.tcpi_retrans, tcp_info.tcpi_fackets, tcp_info.tcpi_last_data_sent, tcp_info.tcpi_last_ack_sent,
		tcp_info.tcpi_last_data_recv, tcp_info.tcpi_last_ack_recv, tcp_info.tcpi_pmtu, tcp_info.tcpi_rcv_ssthresh, 	tcp_info.tcpi_rtt, tcp_info.tcpi_rttvar,tcp_info.tcpi_snd_ssthresh, tcp_info.tcpi_snd_cwnd,	tcp_info.tcpi_advmss,tcp_info.tcpi_reordering );

		// record useful info
		if ( tcp_info.tcpi_advmss > 0 )  {
			nr_tcp_mss_got = tcp_info.tcpi_advmss;
			nr_tcp_window_got = (( tcp_info.tcpi_rcv_ssthresh + nr_tcp_mss_got -1 ) / nr_tcp_mss_got )* nr_tcp_mss_got;
			printf("win got %d\n", nr_tcp_window_got);
		}
	}
	#endif
/* */

	// print end debug line
	if ( nr_tb )
		printf ("ENDDEBUGINFO\n");	

	// bind / connect / send for non raw
	unsigned char * packet = sent_datagram + ip_header_len + tcp_header_len;
	int sent=0;
	int connected=-1;



	// RAW
	int internal_tb_sent_len=-1;
	if ( nr_tb ) {
		nr_tb_doing = 1;
		internal_common_tracebox_main(argc, argv, dest_addr);
		nr_tb_doing = 0;
	} else 
	if ( nr_tb ) {
		char internal_tb_command [1000] ="\0";
		char output[5000]="\0";
		char buffer[1000]="\0";
		char* serv_addr = tb_serv_addr;
		if ( prot3 == 6 ) 
			serv_addr = tb_serv_addr6;
		snprintf( internal_tb_command, 999, "%s %s  -min 64 -print_last_sent %s  ",this_command, serv_addr, tb_params_string);
		printf("internal_tb_command %s\n",  internal_tb_command);

		// open file
		FILE * fp;
		fp = popen( internal_tb_command, "r");
		if (fp == NULL)
		  return;

		// gets ouput from stdout
		strcpy(output, "\0");
		while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		    char* packet_hex_string;
		    //printf("%s", buffer );
	 	    if ( print_nr_tb  == 1)
			printf("%s", buffer );			
		    if ( (packet_hex_string = strstr ( buffer, "Last Packet Sent: 0x" )) != NULL ) {
			packet_hex_string += strlen("Last Packet Sent: 0x");
			printf("%s", packet_hex_string );
			// retrieve packet
			int l = strlen(packet_hex_string)/2;
			printf("l %d\n", l);
			for ( int i = 0; i< l ;i++) {
				int c = 0;
				sscanf(packet_hex_string+2*i, "%2x", &c);
				// printf("%2x ", c);
				memcpy(sent_datagram + i, &c, 1);
			}
			internal_tb_sent_len = l;		
			print_pkt (sent_datagram, l);
		    }
		}
		// close file
		pclose(fp);
	}

	else {
		// bind before connect
		if ( prot3 == 4 ) {
			dst.sin_family = AF_INET;
			dst.sin_addr.s_addr=inet_addr(dest_addr);
			dst.sin_port=htons(dport);

			client4.sin_addr.s_addr = inet_addr(local_addr);
		    	client4.sin_family = af;
			uint16_t port_count = 20000;
			int r = rand_long_int() % 0x10000;
			if ( r <= 1024 )
				r += 1025;
			if ( (nr_keep_port)  &&  ( nr_keeped_port>0) )
				r = nr_keeped_port;
			if ( (nr_custom_port)  &&  ( nr_port>0) )
				r = nr_port;
			for ( int i = r; i<0xffff; i++ ) {
			    	client4.sin_port = htons( i );
				if( bind(nr_sndsock,(struct sockaddr *)&client4 , sizeof(client4) ) <0 )
					; //printf("bind failed %d\n", i);
				else {
					printf("bind done %04x\n", i);
					nr_source_got=i;
					if ( (nr_keep_port)  &&  ( nr_keeped_port<=0) )
						nr_keeped_port = r;
					break;
				}
			}
			server4.sin_addr.s_addr = inet_addr(dest_addr);
		    	server4.sin_family = af;
		    	server4.sin_port = htons( dport );
			if ( nr_tcp_fo == 0 ) {
				connected = connect(nr_sndsock , (struct sockaddr *)&server4 , sizeof(server4));
				if (s<0) {
					printf("connect failed. Error");
				} else {
					printf("connected \n");
				}
			}
		} else if ( prot3 == 6 ) {
			inet_pton(AF_INET6, local_addr, (void *)&client6.sin6_addr.s6_addr);
			client6.sin6_flowinfo = 0;
		    	client6.sin6_family = af;
			client6.sin6_scope_id = 0;
			//client6.sin6_addr = in6addr_any;
			int r = rand_long_int() % 0x10000;
			if ( (nr_keep_port)  &&  ( nr_keeped_port>0) )
				r = nr_keeped_port;
			for ( int i = r; i<0xffff; i++ ) {
			    	client6.sin6_port = htons( i );
				if( bind(nr_sndsock,(struct sockaddr *)&client6 , sizeof(client6))  ) 
					; // printf("bind failed %d\n", i);
				else {
					printf("bind done %d\n", i);
					nr_source_got=i;
					if ( (nr_keep_port)  &&  ( nr_keeped_port<0) )
						nr_keeped_port = r;
					break;
				}
			}
			//memset((char *) &server6, 0, sizeof(server6));
	    		//memmove((char *) &serv_addr.sin6_addr.s6_addr, (char *) server->h_addr, server->h_length);
	//		inet_pton(AF_INET6, tb_serv_addr6, (void *)&tb_serv6.sin6_addr.s6_addr);
			inet_pton(AF_INET6, dest_addr, (void *)&server6.sin6_addr.s6_addr);
			server6.sin6_flowinfo = 0;
		    	server6.sin6_family = af;
		    	server6.sin6_port = htons( dport );
			server6.sin6_scope_id = 0;
	//		server6.sin6_addr = in6addr_any;
			if ( nr_tcp_fo == 0 ) {
				connected = connect(nr_sndsock , (struct sockaddr *)&server6 , sizeof(server6));
				if (s  < 0) {
					printf("connect 6 failed \n");
				} else {
					printf("connected 6 \n");
				}
			}
		}

		
		// alernative connect tcp syn (+ payload ) Fast Open
		#ifndef MSG_FASTOPEN 
		#define MSG_FASTOPEN 0x20000000 
		#endif
		if ( nr_tcp_fo == 1 ) {
			//int nr_sndsock = socket(af, SOCK_STREAM, 0);
			int sent = sendto(nr_sndsock, packet, payload_len, 0x20000000 ,  (const struct sockaddr *) &dst , sizeof(struct sockaddr)  );	
			printf ("sent TFO %d\n", sent);
		}


		// retrieve tcp window value
		if ( nr_prot4 == 6 ) {
			s = getsockopt(nr_sndsock, SOL_SOCKET, SO_RCVBUF, (char *)& rcvbuf, &size);
			printf ("set rcvbuf %d\t%04x\n" , s, rcvbuf);
			if ( rcvbuf == 0x7210*2 )
				nr_tcp_window_got = 0x7210;
			else if ( rcvbuf == 0x0480*2 )
				nr_tcp_window_got = 0x480;
		}
		printf("window got %d\n", nr_tcp_window_got);

		// retrieve tcp_info second time
		struct tcp_info tcp_info;
		int tcp_info_length = sizeof(tcp_info);
		#ifdef SOL_TCP
		if ( getsockopt( nr_sndsock, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_length ) == 0 ) {
			printf("	tcpi_state %u     tcpi_ca_state %u     tcpi_retransmits %u     tcpi_probes %u     tcpi_backoff %u     tcpi_options %u     tcpi_snd_wscale %u     tcpi_rcv_wscale %u    	tcpi_rto %u     tcpi_ato %u     tcpi_snd_mss %u     tcpi_rcv_mss %u    	tcpi_unacked %u     tcpi_sacked %u     tcpi_lost %u     tcpi_retrans %u     tcpi_fackets %u     tcpi_last_data_sent %u     tcpi_last_ack_sent %u    tcpi_last_data_recv %u     tcpi_last_ack_recv %u     tcpi_pmtu %u     tcpi_rcv_ssthresh 0x%x     	tcpi_rtt %u     tcpi_rttvar %u    tcpi_snd_ssthresh 0x%x     tcpi_snd_cwnd %u    	tcpi_advmss %u    tcpi_reordering %u    tcpi_rcv_space 0x%x\n",

			tcp_info.tcpi_state, tcp_info.tcpi_ca_state, tcp_info.tcpi_retransmits, tcp_info.tcpi_probes, tcp_info.tcpi_backoff, tcp_info.tcpi_options, tcp_info.tcpi_snd_wscale, tcp_info.tcpi_rcv_wscale,	tcp_info.tcpi_rto, tcp_info.tcpi_ato,
			tcp_info.tcpi_snd_mss,	tcp_info.tcpi_rcv_mss,	tcp_info.tcpi_unacked, tcp_info.tcpi_sacked, tcp_info.tcpi_lost, tcp_info.tcpi_retrans, tcp_info.tcpi_fackets, tcp_info.tcpi_last_data_sent, tcp_info.tcpi_last_ack_sent,
			tcp_info.tcpi_last_data_recv, tcp_info.tcpi_last_ack_recv, tcp_info.tcpi_pmtu, tcp_info.tcpi_rcv_ssthresh, 	tcp_info.tcpi_rtt, tcp_info.tcpi_rttvar,tcp_info.tcpi_snd_ssthresh, tcp_info.tcpi_snd_cwnd,	tcp_info.tcpi_advmss,tcp_info.tcpi_reordering, tcp_info.tcpi_rcv_space );
			

int s1, s2;
getsockopt(nr_sndsock, SOL_SOCKET, SO_SNDBUF, (char *)&s1, sizeof(s1));
printf("SO_SNDBUF 0x%x\n", s1);
s1=0x10000;
getsockopt(nr_sndsock, SOL_SOCKET, SO_SNDBUF, (char *)&s1, sizeof(s1));
printf("SO_SNDBUF 0x%x\n", s1);

			// record if synacked
			if (tcp_info.tcpi_state == 1 )
				nr_tcp_synack_got = 1;

			// record options synacked
			nr_tcp_sack_perm_tcpi = ( (tcp_info.tcpi_options & TCPI_OPT_SACK) > 0);
			nr_tcp_ts_tcpi = 	((tcp_info.tcpi_options & TCPI_OPT_TIMESTAMPS) > 0);
			nr_tcp_ws_tcpi =	((tcp_info.tcpi_options & TCPI_OPT_WSCALE) > 0);
			#ifdef TCPI_OPT_SYN_DATA
			nr_tcp_syn_data_acked_tcpi =	((tcp_info.tcpi_options & TCPI_OPT_SYN_DATA) > 0);
			#endif 	
			//nr_tcp_mss_tcpi =	((tcp_info.tcpi_options & TCPI_OPT_MSS) > 0);
			printf("tcpi_options  SP %d WS %d TS %d       FO %d\n", nr_tcp_sack_perm_tcpi, nr_tcp_ws_tcpi, nr_tcp_ts_tcpi, nr_tcp_syn_data_acked_tcpi);


			// 
			if ( nr_tcp_ws_tcpi ) {
				nr_tcp_ws_got = tcp_info.tcpi_rcv_wscale;
				nr_tcp_ws_back_got = tcp_info.tcpi_snd_wscale;
			}
			printf("ws got %d %d\n",  nr_tcp_ws_got, nr_tcp_ws_back_got);
			
			// record mss, windowsize and back mss
			if ( tcp_info.tcpi_advmss > 0 )  {
				nr_tcp_mss_got = tcp_info.tcpi_advmss;
				if ( nr_tcp_ts_tcpi )
					nr_tcp_mss_got += 12;
				nr_tcp_window_got =  tcp_info.tcpi_rcv_ssthresh;
				printf("mss got%d %d\n", s, nr_tcp_mss_got);
				printf("win got %d\n", nr_tcp_window_got);
			}
			int val;	
			int val_size;		
			s = getsockopt(nr_sndsock, IPPROTO_TCP, TCP_MAXSEG, &val, &val_size);
			nr_tcp_mss_back_got = val;
			// val is always 0, why?
			nr_tcp_mss_back_got =tcp_info.tcpi_snd_mss;
			if ( nr_tcp_ts_tcpi )
				nr_tcp_mss_back_got += 12;
			printf("mss back got%d %d %04x\n", s, nr_tcp_mss_back_got, nr_tcp_mss_back_got);

			// record ws and back ws
			if ( nr_tcp_ws_tcpi  )  {
				nr_tcp_ws_reliable = 1;
				nr_tcp_ws_got = tcp_info.tcpi_rcv_wscale ;
				nr_tcp_ws_back_got = tcp_info.tcpi_snd_wscale;
			}

			// record info about acked sacked 
		}	
		#endif

		// correct payload_len if IP Fragmentation test
		printf ("nr frag %d %d\n", nr_frag, nr_frag_mf);
		if ( nr_frag || nr_frag_mf ) {
			int val = 0;
			int val_size;
			int s = getsockopt(nr_sndsock, IPPROTO_IP,  IP_MTU , &val, &val_size);		
			if ( val == 0 )
				val = 1500;
			int head;
			if ( nr_prot4 == 6 )	
				head = 20;
			else if ( nr_prot4 == 17 )	
				head = 8;

			if (payload_len = val - ip_header_len - head > 0 )
				if ( nr_frag ) 
					payload_len = val - ip_header_len - head;
				else if ( nr_frag_mf )
					payload_len = val - ip_header_len - head + 10;
		printf ("nr frag s val iph h %d %d %d %d\n", s, val, ip_header_len, head);	

		}
	
		// (fake or true) tcp payload
		if ( nr_prot4 == 6) {
			if ( (!nr_tcp_no_pay) || (nr_tcp_pay == 1) ) // fake or true pay
				if ( nr_tcp_fo != 1 ) {
					// only if connect() succeded
					if ( connected != -1  ) {
						sleep(1);
						sent = sendto(nr_sndsock, packet, payload_len, MSG_OOB * nr_tcp_urg,  (const struct sockaddr *) &dst , sizeof(struct sockaddr)  );
						if ( nr_tcp_coalesc )  {
							char coalesc_packet[10]= "COALESC!";
							usleep(100000);
							for ( int i = 0; i < strlen(coalesc_packet); i++ ) {
								usleep(10000);
								sent = sendto(nr_sndsock, coalesc_packet + i, 1, 0,  (const struct sockaddr *) &dst , sizeof(struct sockaddr)  );
							}
						}
						printf("sent tcp pay  %d\n", sent);
						nr_tcp_urgptr_got = sent*nr_tcp_urg;
					}
				}
		}

		#ifdef SOL_TCP
		if ( getsockopt( nr_sndsock, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_length ) == 0 ) {
			// check if everthing acked
			nr_tcp_payack_got = (tcp_info.tcpi_unacked==0);	
printf("unacked %d sacked %d \n", tcp_info.tcpi_unacked, tcp_info.tcpi_sacked);
		}		
		#endif
		
		// payload UDP
		if ( prot == 17) {
			tcp_header_len=8;
			sent = sendto(nr_sndsock, packet, payload_len, 0,  (const struct sockaddr *) &dst , sizeof(struct sockaddr)  );
			printf ("sent UDP %d\n", sent);
			// then wait to receive udp and answer
			pthread_t thread_id;
			pthread_create( &thread_id , NULL ,  udp_echo , (void*) &nr_sndsock);

		}

		// retrieve wayback ttl
		// only udp

		/*	
		sent   = sendto(nr_sndsock, packet, payload_len, 0,  (const struct sockaddr *) &dst , sizeof(struct sockaddr)  );

		// int sfd = socket(AF_INET, SOCK_STREAM, 0);
		// sendto(sfd, packet, payload_len, MSG_FASTOPEN,  (const struct sockaddr *) &dst , sizeof(struct sockaddr)  );
	

		if (sent <= 0)
			printf("Error! Send =%d\n", sent);
		else
			printf("Sent=%d\n", sent);

		*/
	
		//print_pkt_text(packet, sent);
		//print_pkt(packet,sent);


		// retrieve tcp_info AGAIN, the first was after SYN
		if ( nr_print_payack==1 ) {
			sleep(3);
			#ifdef SOL_TCP
			if ( getsockopt( nr_sndsock, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_length ) == 0 ) {
				printf("	tcpi_state %u     tcpi_ca_state %u     tcpi_retransmits %u     tcpi_probes %u     tcpi_backoff %u     tcpi_options %u     tcpi_snd_wscale %u     tcpi_rcv_wscale %u    	tcpi_rto %u     tcpi_ato %u     tcpi_snd_mss %u     tcpi_rcv_mss %u    	tcpi_unacked %u     tcpi_sacked %u     tcpi_lost %u     tcpi_retrans %u     tcpi_fackets %u     tcpi_last_data_sent %u     tcpi_last_ack_sent %u    tcpi_last_data_recv %u     tcpi_last_ack_recv %u     tcpi_pmtu %u     tcpi_rcv_ssthresh 0x%x     	tcpi_rtt %u     tcpi_rttvar %u    tcpi_snd_ssthresh %u     tcpi_snd_cwnd %u    	tcpi_advmss %u    tcpi_reordering %u    \n",

				tcp_info.tcpi_state, tcp_info.tcpi_ca_state, tcp_info.tcpi_retransmits, tcp_info.tcpi_probes, tcp_info.tcpi_backoff, tcp_info.tcpi_options, tcp_info.tcpi_snd_wscale, tcp_info.tcpi_rcv_wscale,	tcp_info.tcpi_rto, tcp_info.tcpi_ato,
				tcp_info.tcpi_snd_mss,	tcp_info.tcpi_rcv_mss,	tcp_info.tcpi_unacked, tcp_info.tcpi_sacked, tcp_info.tcpi_lost, tcp_info.tcpi_retrans, tcp_info.tcpi_fackets, tcp_info.tcpi_last_data_sent, tcp_info.tcpi_last_ack_sent,
				tcp_info.tcpi_last_data_recv, tcp_info.tcpi_last_ack_recv, tcp_info.tcpi_pmtu, tcp_info.tcpi_rcv_ssthresh, 	tcp_info.tcpi_rtt, tcp_info.tcpi_rttvar,tcp_info.tcpi_snd_ssthresh, tcp_info.tcpi_snd_cwnd,	tcp_info.tcpi_advmss,tcp_info.tcpi_reordering );
			}
		
			// check if everthing acked
			nr_tcp_payack_got = (tcp_info.tcpi_unacked==0);			
			#endif
		}
		
			
	} // if !se ?



	
	int recv_len = 0;

	int tcp_rec_len=0;
	int tcp_sent_len=0;
	// get lengths
	if ( nr_tb ) {
		tcp_sent_len = 	internal_tb_sent_len - ip_header_len;
	}
	else {
		tcp_sent_len = tcp_header_len + payload_len;
	}	
	int quoted_tcp_offset=0;

	if (!se ) {
	// wait answer
	// set timeout
	struct timeval tv;
	int NR_SENT_PACKET_TIMEOUT = 15 +10 * nr_tcp_pay;
	tv.tv_sec = NR_SENT_PACKET_TIMEOUT; 		// increase timeout
	tv.tv_usec = 0; 
	s  = setsockopt(tb_serv_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));	
	// printf ("set timeout %d\n" , s);
	// get answer
	memset(recv_pkt,0,DATAGRAM_SIZE);
	recv_len = recv(tb_serv_sock , recv_pkt , sizeof(recv_pkt) , 0 ) ;
	//printf("STARTDEBUGINFO\n");
	if( recv_len< 0) {
		// printf("recv failed %d\n", recv_len);	
	} else {
		// print_pkt(recv_pkt, recv_len);
		// printf("recv ok %d\n", recv_len);
	}
	//printf("ENDDEBUGINFO\n");	
	// get lengths
	if ( nr_tb ) {
		tcp_sent_len = 	internal_tb_sent_len - ip_header_len;
	}
	else {
		tcp_sent_len = tcp_header_len + payload_len;
	}	
	tcp_rec_len = recv_len - ip_header_len;
	quoted_tcp_offset = ip_header_len;

	// print results
	//printf("printing hex %d\n", recv_len);
	if ( !hide_pay )
	//print_pkt(recv_pkt, recv_len);
	//printf(recv_pkt);
	// align packet 
	if (prot3 == 4 ) {
		rec_ip = recv_pkt;
		rec_tcp = recv_pkt + 20;
		rec_udp = recv_pkt + 20;
	} else if (prot3 == 6 ) {
		rec_ip6 = recv_pkt;
		rec_tcp = recv_pkt + 40;
		rec_udp = recv_pkt + 40;
	}
	} // if !se



	if ( nr_tb == 1 ) {
		unsigned char old_sent[200];
		memcpy( old_sent, sent_datagram, 200);
		set_default_fields(sent_datagram, seq=1, ttl=64, 1, 0);
		memcpy(default_pkt, sent_datagram, ip_header_len + tcp_header_len);
		memcpy(sent_datagram, old_sent, ip_header_len + tcp_header_len);
		reset_chksumwrg();
		// correct IP::DestAddr, it's not set
	} 
	else {
		// create default packet
		set_default_fields(sent_datagram, seq=1, ttl=64, 1, 0);
		// save default packet
		memcpy(default_pkt, sent_datagram, ip_header_len + tcp_header_len);
		// customize packet
		set_custom_fields(sent_datagram, seq=1, ttl=64, 1, 0);
		// correct some fields
		// IP
		if ( prot3 == 4 ) {
			struct new_iphdr * n_sent_ip = sent_ip;
			// retrieve MF flag (UDP only)
			if ( nr_prot4 == 17 ) {
				int val = 0;
				int val_size;
				getsockopt(nr_sndsock, IPPROTO_IP,  IP_MTU , &val, &val_size);
				if ( val == 0 )
					val = 1500;
				if ( ip_header_len + tcp_header_len + payload_len > val	 ) {
					nr_mf_got = 1;
					nr_df_got = 0;
				}

			}			
			n_sent_ip->mf = nr_mf_got;
			n_sent_ip->df = nr_df_got;
	/*	
	print_pkt(n_sent_ip,20);
	print_pkt(sent_datagram, 20);
	print_pkt(default_pkt, 20);
	*/
		}

		// UDP
		if ( nr_prot4 == 17 ) {
			sent_udp->source = htons(nr_source_got);
			sent_udp->dest = htons(nr_dest_got);
			sent_udp->len = htons(sizeof(struct udphdr) + payload_len);
			sent_udp->check = 0x0; 	// calculate checksum
		
		}

		// TCP
		if ( nr_prot4 == 6 ) {
			sent_tcp->source = htons(nr_source_got);
			sent_tcp->dest = htons(nr_dest_got);

			if (nr_tcp_window_got>0xffff && (!nr_tcp_pay || (nr_tcp_pay && !nr_tcp_ws_tcpi)) )
				nr_tcp_window_got=0xffff;
			if (nr_tcp_window_got>0xffff && nr_tcp_pay && nr_tcp_ws_tcpi) {
				//int ws_factor = pow(2,nr_tcp_ws_got);
				//nr_tcp_window_got = ceil(nr_tcp_window_got/ws_factor);
				int ws_factor=1;
				for(int i=0; i<nr_tcp_ws_got; i++)
					ws_factor*=2;
				nr_tcp_window_got = nr_tcp_window_got / ws_factor + 1* (nr_tcp_window_got % ws_factor != 0);				
			}
			sent_tcp->window = htons(nr_tcp_window_got);

			sent_tcp->urg_ptr = htons (nr_tcp_urgptr_got);
		
		}
		

		// add tcp options and payload and correct lengths
		if (nr_prot4 == 6 ) {
			// delete fake pay if present
			char * sent_pay = sent_datagram + ip_header_len +tcp_header_len;
			memcpy (pay_packet, sent_datagram + tcp_header_len + ip_header_len, payload_len);
			memset(sent_datagram + tcp_header_len + ip_header_len, 0, payload_len);
			//payload_len = 0;
			tcp_header_len = 20;
			
			int opts_len= 0;
			// tcp options

			// syn 
			if ( (nr_tcp_pay == 0)  ||  (nr_tcp_fo) ){
				unsigned char opts[20] = {0x02, 0x04, 0xff, 0xff, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x0c, 0x7f, 0xd8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06};
				unsigned char opts_md5 [32] = {0x01, 0x01, 0x13, 0x12, 0x1b, 0x76, 0xab, 0xb7, 0xd4, 0xae, 0x22, 0xe4, 0x76, 0xb9, 0x82, 0x79, 0xa5, 0x02, 0x2a, 0xb8, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02, 0x01, 0x03, 0x03, 0x02 };
				unsigned char opts_fo[24] = {0x02, 0x04, 0xff, 0xff, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x0c, 0x7f, 0xd8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06, 0xfe, 0x04, 0xf9, 0x89 };
				// set hex string options

				if ( nr_tcp_fo == 1 )  {
					memcpy ( sent_datagram + ip_header_len + tcp_header_len, opts_fo, sizeof(opts_fo));
					opts_len = sizeof ( opts_fo );
				} else if ( nr_tcp_md5 == 1 ) {
					memcpy ( sent_datagram + ip_header_len + tcp_header_len, opts_md5, sizeof(opts_md5));
					opts_len = sizeof ( opts_md5 );
				} else {
					memcpy ( sent_datagram + ip_header_len + tcp_header_len, opts, sizeof(opts));
					opts_len = sizeof ( opts );
				}
			
				// correct MSS value
				// nr_tcp_mss_got = mss_value;
				struct tcp_option_mss * t = sent_datagram + ip_header_len + tcp_header_len ;
				if ( ( t->kind == 2 ) && (t->len == 4 ) )
					t->mss = htons(nr_tcp_mss_got);

				// correct WS value
				struct tcp_option_windowscale * ws = sent_datagram + ip_header_len + tcp_header_len + 17 ;
				if ( (nr_tcp_ws_tcpi) || (nr_tcp_ws!=-1)) 
					if ( ( ws->kind == 3 ) && (ws->len == 3 ) )
						ws->value = (nr_tcp_ws_got);
		
			} else {
				// tcp pay
				// change flags
				if ( !nr_tcp_fo ) {
					sent_tcp->syn = 0;
					sent_tcp->ack = 1;
					sent_tcp->psh = 1;
					sent_tcp->urg = nr_tcp_urgptr_got > 0;
				}
				// tcp ts option is the only to take into account
				unsigned char opts_ts[12] = {0x01, 0x01, 0x08, 0x0a, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x0c, 0x7f, 0xd8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06, 0xfe, 0x04, 0xf9, 0x89 };	
				if ( nr_tcp_ts_tcpi ) {
					memcpy ( sent_datagram + ip_header_len + tcp_header_len, opts_ts, sizeof(opts_ts));
					opts_len += 12;
				}
					
			}

			// correct doff
			tcp_header_len += opts_len;
			sent_tcp->doff += (opts_len +3) / 4;

			// correct pay
			if ( nr_tcp_pay )  {
				memcpy ( sent_datagram + tcp_header_len + ip_header_len, pay_packet, payload_len);
				//print_pkt (sent_datagram + tcp_header_len + ip_header_len, payload_len);
				
			}
			else {
				payload_len = 0;
			}

			// correct ip len with opts len and payload len
			if ( prot3 == 4 )
				sent_ip->tot_len = htons( ntohs (sent_ip->tot_len) + opts_len + payload_len);
			else if (prot3 == 6 )
				sent_ip6->payload_len = htons( ntohs (sent_ip6->payload_len) + opts_len  + payload_len);

		} else if (nr_prot4 == 17 ) {
			// payload is already there fot UDP
			// correct ip len with payload len
			if ( prot3 == 4 )
				sent_ip->tot_len = htons( ntohs (sent_ip->tot_len)  + payload_len);
			else if (prot3 == 6 )
				sent_ip6->payload_len = htons( ntohs (sent_ip6->payload_len)  + payload_len);
		}


		// correct ip fields
		if ( prot3 == 4 ) {
			// TOS
			if ( nr_prot4 == 6 )
				sent_ip->tos = ( nr_tos_got / 4 ) * 4;	
			else if ( nr_prot4 == 17 )
				sent_ip->tos = nr_tos_got;	
			// TTL
			sent_ip->ttl = nr_ttl_got;

			// DF
			((struct new_iphdr*) sent_ip)->df = nr_df_got;
			// MF
			((struct new_iphdr*) sent_ip)->mf = nr_mf_got;

		}
		else if (prot3 == 6 ) {
			// TOS
			if ( nr_prot4 == 6 )
				set_trafficclass(sent_ip6, (nr_tc_got / 4 ) * 4 );
			else if ( nr_prot4 == 17 )
				set_trafficclass(sent_ip6, nr_tc_got );
			// HOP LIMIT
			sent_ip6->hop_limit = nr_hl_got;


		}


		// print shoulhavebeensent packet
		if (!hide_pay)
			; // print_pkt(sent_datagram,tcp_header_len + ip_header_len +payload_len);
	}



	// clean mod packets
	memset(mod_pkt, 0 , DATAGRAM_SIZE);	
	memset(mod_pkt_msk, 0, DATAGRAM_SIZE);	


	// print end debug line
	if ( !nr_tb  )
		printf ("ENDDEBUGINFO\n");	


	// print SYN info if it's TCP PAY probe
	if (!nr_tb &&  nr_tcp_pay && nr_print_syn  && (nr_prot4==6) ) {
			// introductive text
		char* serv_addr_4_6 = tb_serv_addr;
		if ( prot3 == 6)
			serv_addr_4_6 = tb_serv_addr6;
		printf("traceboxing from  %s  to  %s\n",  local_addr, dest_addr);
		// show source	
		printf("  0:  ");
		if (prot3 == 4 )
			printf("%-15s  ", local_addr);	
		else if ( prot3 == 6)
			printf("%-39s  ", local_addr);	
		// print info about packet
		// print_essential_pkt_info(sent_datagram +ip_header_len, payload_len, recv_only);
		if ( prot3 ==4 )
			printf("[TCP Syn]  ");
		else if (prot3==6)
			printf("[TCP Syn (Ipv6)]  ");
		// set compare default variables
		nr_tcp_opt_cd = 1;

		if ( compare_default )
			;// compare_packets_default( sent_datagram, 0, default_pkt, 0);

		// print at least DestPort and TTL/HL
		// dest port		
		if (dport != 80)
			printf ("TCP::DestPort (%04x)  ", dport);
		// ttl
		if (prot3 == 4 )
			printf("IP:TTL (%02x)  ", nr_ttl_got);	
		else if ( prot3 == 6)
			printf("IPv6:HopLimit (%02x)  ", nr_ttl_got);	
		printf("\n");

		int extimated_ttl = 1 + ( (prot3 == 6 ) ?  (sent_ip6->hop_limit - rec_ip6->hop_limit ) : (sent_ip->ttl - rec_ip->ttl) );

		if (!se) {
			if ( ( extimated_ttl > 0 ) && ( extimated_ttl < 64 ) && ( recv_len > 0 )) {
				printf("%3d:  ", extimated_ttl);
				nr_extimated_ttl = extimated_ttl;
			}
			else 
				printf("   :  ");
		} else 
			printf("%3d:  ", nr_ttl_got);

		// print tcp options synacked or not
		if ( nr_tcp_synack_got == 1 ) {
			// print server as a hop
			if (prot3 == 4 )
				printf("%-15s  ", dest_addr);	
			else if ( prot3 == 6)
				printf("%-39s  ", dest_addr);
			// print ip and tcp info avaible 
			if (prot3 == 4 )
				printf("[TCP Syn Ack]  ");
			else if ( prot3 == 6)
				printf("[TCP Syn Ack (IPv6)]  ");
			if (  nr_tcp_mss_back_got != 536 )
				printf("TCP::Option_MSS (%04x->%04x)  ", nr_tcp_mss_got, nr_tcp_mss_back_got);
			if (  nr_tcp_sack_perm_tcpi )
				printf("=TCP::Option_Sack_Perm  ");
			else 
				printf("-TCP::Option_Sack_Perm  ");
			if (  nr_tcp_ws_tcpi )
				printf("TCP::Option_WindowScale (%02x->%02x)  ", nr_tcp_ws_got, nr_tcp_ws_back_got);
			else 
				printf("-TCP::Option_WindowScale  ");
			if (  nr_tcp_ts_tcpi )
				printf("TCP::Option_Timestamp  ");
			else 
				printf("-TCP::Option_Timestamp  ");
		} else
			printf("* ");

			printf("\n");
	
	}
		

	// introductive text
	char* serv_addr_4_6 = tb_serv_addr;
	if ( prot3 == 6)
		serv_addr_4_6 = tb_serv_addr6;
	printf("traceboxing from  %s  to  %s\n",  local_addr, dest_addr);
	// show source	
	printf("  0:  ");
	if (prot3 == 4 )
		printf("%-15s  ", local_addr);	
	else if ( prot3 == 6)
		printf("%-39s  ", local_addr);	
	// print info about packet
	print_essential_pkt_info(sent_datagram +ip_header_len, payload_len, recv_only);
	// set compare default variables
	nr_tcp_opt_cd = 1;

	if ( compare_default )
		compare_packets_default( sent_datagram, 0, default_pkt, 0);
	printf("\n");
	// set compare default variables
	nr_tcp_opt_cd = 0;


	int extimated_ttl = 0;
	if (!se) {
	// try to get ttl hoplimit difference
	//rec_ip6 = rec_pkt;
	int extimated_ttl = 1 + ( (prot3 == 6 ) ?  (sent_ip6->hop_limit - rec_ip6->hop_limit ) : (sent_ip->ttl - rec_ip->ttl) );
	// printf("extimated_ttl %3d %d %d %d %d \n", extimated_ttl,  sent_ip->ttl ,rec_ip->ttl ,sent_ip6->hop_limit ,rec_ip6->hop_limit);
	if ( ( extimated_ttl > 0 ) && ( extimated_ttl < 64 ) && ( recv_len > 0 )) {
		printf("%3d:  ", extimated_ttl);
		nr_extimated_ttl = extimated_ttl;
	}
	else 
		printf("   :  ");
	
	// compare only if a packet has actually been received
	if ( recv_len <= 0 )
		printf("* \n");
	else {
		// print server as a hop
		if (prot3 == 4 )
			printf("%-15s  ", serv_addr_4_6);	
		else if ( prot3 == 6)
			printf("%-39s  ", serv_addr_4_6);	
		// print quoting ratio from server
		int server_quoted_len = recv_len - ip_header_len;
		int sent_to_server_len = tcp_header_len + payload_len;
		if ( server_quoted_len >  sent_to_server_len )
			server_quoted_len = sent_to_server_len;
		printf("[%d/%d]  ", server_quoted_len, sent_to_server_len);

		// TTL (ipv4 only)
		if ( prot3 == 4 )
			ttl = nr_ttl_got;
		else if ( prot3 == 6)
			ttl = nr_hl_got;


		// IP
		if ( prot3 == 4 ) {
			compare_ip_packets(sent_datagram, 0, recv_pkt,  0, 20, mod_pkt, mod_pkt_msk, ttl);
		} else if (prot3 == 6 ) {
			compare_ip6_packets(sent_datagram, 0, recv_pkt, 0, 40 , mod_pkt, mod_pkt_msk, ttl);
		}
		// TCP - UDP
		if (prot == 6 ) {
			compare_tcp_packets(sent_datagram, ip_header_len, recv_pkt, quoted_tcp_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk);
			compare_tcp_options(sent_datagram, ip_header_len, recv_pkt, quoted_tcp_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk, 0);
		}
		else if (prot == 17) 
			compare_udp_packets(sent_datagram, ip_header_len, recv_pkt, quoted_tcp_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk);
		// every prot
		// correct!
			if ( !hide_pay )
			compare_payload(sent_datagram, ip_header_len, recv_pkt, quoted_tcp_offset, tcp_rec_len, tcp_sent_len, mod_pkt, mod_pkt_msk);

		printf("\n");
	}
	} // if !se


	if (!nr_tb && nr_print_synack && (nr_tcp_pay==0) && (nr_prot4==6)) {
		// print ttl extimated or set
		if ( ( extimated_ttl > 0 ) && ( extimated_ttl < 64 ) && ( recv_len > 0 )) {
			printf("%3d:  ", extimated_ttl);
			nr_extimated_ttl = extimated_ttl;
		}
		else 
			printf("   :  ");

		if ( nr_tcp_synack_got == 1 ) {
			// print server as a hop
			if (prot3 == 4 )
				printf("%-15s  ", dest_addr);	
			else if ( prot3 == 6)
				printf("%-39s  ", dest_addr);
			// print ip and tcp info avaible 
			if (prot3 == 4 )
				printf("[TCP Syn Ack]  ");
			else if ( prot3 == 6)
				printf("[TCP Syn Ack (IPv6)]  ");
			// print test results (TCP FO for now)
			if (  nr_test_fo == 1 )
				printf("Test::TCP_FastOpen (%s)  ", nr_tcp_syn_data_acked_tcpi == 1 ? "Succeded!": "Failed!");
			// print tcp options synacked or not
			if (  nr_tcp_mss_back_got != 536 )
				printf("TCP::Option_MSS (%04x->%04x)  ", nr_tcp_mss_got, nr_tcp_mss_back_got);
			if (  nr_tcp_sack_perm_tcpi )
				printf("TCP::Option_Sack_Perm  ");
			else 
				printf("-TCP::Option_Sack_Perm  ");
			if (  nr_tcp_ws_tcpi )
				printf("TCP::Option_WindowScale (%02x->%02x)  ", nr_tcp_ws_got, nr_tcp_ws_back_got);
			else 
				printf("-TCP::Option_WindowScale  ");
			if (  nr_tcp_ts_tcpi )
				printf("TCP::Option_Timestamp  ");
			else 
				printf("-TCP::Option_Timestamp  ");
			}
			else
				printf("* ");

		printf("\n");
	}


	// ask for back tracebox
	int recv_tbback_len=-1;
	if (!se) {
	if ( nr_back == 1 ) {
		char message[20] = "MORE";
		write(tb_serv_sock , message , strlen(message));
		// printf ("sending message: %s\n", message);
		// add an udp answer!
		struct timeval tv;
		tv.tv_sec = NR_TRACEBOX_BACK_TIMEOUT; 		// increase timeout
		tv.tv_usec = 0; 
		s  = setsockopt(tb_serv_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));	
		memset(answer_text,0,ANSWER_TEXT_SIZE);
		recv_tbback_len = recv(tb_serv_sock , answer_text , ANSWER_TEXT_SIZE , MSG_WAITALL  );
		
		answer_text[recv_tbback_len]='\0';
		if( recv_tbback_len< 0) {
			;//puts("recv failed");	
		} else
			;//print_pkt_text(answer_pkt, recv_len);
		nr_tracebox_back_ended = 1;

		// tracebox back will be printed later					
	}
	} // if !se

	
	// last receive and unacked control for TCP pay
	if (nr_print_pay_back && (nr_prot4==6) && (nr_tcp_pay==1) ) {
		struct timeval tv;
		tv.tv_sec = 3; 			// 1 sec to iterate
		tv.tv_usec = 0; 
		s  = setsockopt(nr_sndsock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));	
		int recv_len=-1;
		struct sockaddr_in d;
		int ds=sizeof(d);
		nr_answer_len = recv(nr_sndsock , nr_answer_pkt , DATAGRAM_SIZE, MSG_WAITALL ) ;
		#ifdef SOL_TCP
		if ( getsockopt( nr_sndsock, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_length ) == 0 ) {
			// check if everthing acked
			nr_tcp_payack_got = (tcp_info.tcpi_unacked==0);	
printf("unacked %d sacked %d \n", tcp_info.tcpi_unacked, tcp_info.tcpi_sacked);
		}		
		#endif
		//printf("tcp ack %d   recv %d\n", nr_tcp_payack_got, nr_answer_len);
	}

	// print last line for UDP or TCP pay (ack)
	if (nr_print_pay_back && ( nr_tcp_pay || (nr_prot4 == 17) ) ) {
		// 
		if ( ( extimated_ttl > 0 ) && ( extimated_ttl < 64 ) && ( recv_len > 0 )) {
			printf("%3d:  ", extimated_ttl);
			nr_extimated_ttl = extimated_ttl;
		}
		else 
			printf("   :  ");

		if ( (nr_answer_len >= 0) || ((nr_prot4==6) && (nr_tcp_payack_got==1))) {
			// print server as a hop
			if (prot3 == 4 )
				printf("%-15s  ", dest_addr);	
			else if ( prot3 == 6)
				printf("%-39s  ", dest_addr);	
			// print prot4
			if ( nr_prot4==6)
				printf("[TCP");
			else if ( nr_prot4==17)
				printf("[UDP");
			// print ack for tcp
			if ( nr_prot4==6)
				if (nr_tcp_payack_got==1)
					printf(" Ack");
			// print answer length
			if ( nr_answer_len > 0 )
				if ( nr_prot4==6)
					printf(" %d bytes", nr_answer_len);
				if ( nr_prot4==17)
					printf(" %d bytes", nr_answer_len);
			// print IP version
			if (prot3==6)		
				printf("(IPv6)");
			printf("]");
		}
		else
				printf("* ");

			printf("\n");
	}

	// print tracebox back (received before)
	if (!se) {
	if (nr_back==1) {
	if ( recv_tbback_len >= 0 );
	int start = 0;
	while ( (answer_text[start] == 0) && start < recv_tbback_len)
		start++;
	if ( start < recv_tbback_len )
		printf(answer_text +start);
	}
	} // if !se
	
	// TCP REPAIR QUEUE
	/*
	{
	int val = 0;
	int val_size = 0;
	val  = 1;
	val_size = sizeof(val);
	s = setsockopt ( nr_sndsock, SOL_TCP, TCP_REPAIR, &val, val_size);
	val  = TCP_SEND_QUEUE;
	s = setsockopt ( nr_sndsock, SOL_TCP, TCP_REPAIR_QUEUE, &val, val_size);
	printf( "val %d %d %d\n", s, val, val_size);
	s = getsockopt ( nr_sndsock, SOL_TCP, TCP_QUEUE_SEQ, &val, &val_size);
	printf( "val %d %08x %d\n", s, val, val_size);
	}
	*/

	// TCP last infos
	/*
	struct tcp_info tcp_info;
	int tcp_info_length = sizeof(tcp_info);
	#ifdef SOL_TCP
	if ( getsockopt( nr_sndsock, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_length ) == 0 ) {
			printf("	tcpi_state %u     tcpi_ca_state %u     tcpi_retransmits %u     tcpi_probes %u     tcpi_backoff %u     tcpi_options %u     tcpi_snd_wscale %u     tcpi_rcv_wscale %u    	tcpi_rto %u     tcpi_ato %u     tcpi_snd_mss %u     tcpi_rcv_mss %u    	tcpi_unacked %u     tcpi_sacked %u     tcpi_lost %u     tcpi_retrans %u     tcpi_fackets %u     tcpi_last_data_sent %u     tcpi_last_ack_sent %u    tcpi_last_data_recv %u     tcpi_last_ack_recv %u     tcpi_pmtu %u     tcpi_rcv_ssthresh 0x%x     	tcpi_rtt %u     tcpi_rttvar %u    tcpi_snd_ssthresh %u     tcpi_snd_cwnd %u    	tcpi_advmss %u    tcpi_reordering %u    \n",

			tcp_info.tcpi_state, tcp_info.tcpi_ca_state, tcp_info.tcpi_retransmits, tcp_info.tcpi_probes, tcp_info.tcpi_backoff, tcp_info.tcpi_options, tcp_info.tcpi_snd_wscale, tcp_info.tcpi_rcv_wscale,	tcp_info.tcpi_rto, tcp_info.tcpi_ato,
			tcp_info.tcpi_snd_mss,	tcp_info.tcpi_rcv_mss,	tcp_info.tcpi_unacked, tcp_info.tcpi_sacked, tcp_info.tcpi_lost, tcp_info.tcpi_retrans, tcp_info.tcpi_fackets, tcp_info.tcpi_last_data_sent, tcp_info.tcpi_last_ack_sent,
			tcp_info.tcpi_last_data_recv, tcp_info.tcpi_last_ack_recv, tcp_info.tcpi_pmtu, tcp_info.tcpi_rcv_ssthresh, 	tcp_info.tcpi_rtt, tcp_info.tcpi_rttvar,tcp_info.tcpi_snd_ssthresh, tcp_info.tcpi_snd_cwnd,	tcp_info.tcpi_advmss,tcp_info.tcpi_reordering );
		}			
	#endif
	*/
		
	// close socket
	close(tb_serv_sock);
	close(nr_sndsock);

	return 0;
}

int NR_traceroute_ping ( ) {
	int stars = 0;
	int tr_ping_nr_max_stars = 3;
	int tr_ping_nr_row_stars = 1;
	int timeout = 3; 
	bool reached_dest=0;
	int  ttl = 1;
	FILE* fp;
	char command[100];
	snprintf(command, 99, "ping -c 1 -n -t %d", ttl);
	char buffer[1000];
	char output[2000] = "\0";
	memset(output, 0, sizeof(output));
	const char left_string[]="rom";
	const char right_string[]= " icmp_seq";
	char address [50];

	// getifaddres to have local_addr
	get_ifaddrs();

	// print intro
	printf("traceboxing from  %s  to  %s  \n", local_addr, dest_addr);

	// print line 0
	printf("  0:  ");
	printf("%-15s  ", local_addr);
	printf("[Non Rooted Traceroute ICMP]  ");
	printf("\n");


	for ( int i= 1; ( (i<64) && (stars < tr_ping_nr_max_stars ) && (!reached_dest) ); i++) {
		ttl = i;
		// print line i
		printf("%3d:  ", ttl);	
		
		//
		for ( int j=0; j<repeat_tr_ping_nr; j++) {
			// new command	
			snprintf(command, 99, "ping -c 1 -n -W %d -t %d %s", timeout, ttl, dest_addr);
		
			// open file
			fp = popen(command, "r");
			if (fp == NULL)
			  return;

			// gets ouput from stdout
			strcpy(output, "\0");
			while (fgets(buffer, sizeof(buffer), fp) != NULL) {
			    strcat(output, buffer);
			    //printf("%s", buffer);
			}
			// close file
			pclose(fp);

			// analyze string
			char* s1 =strstr(output, left_string);
			if ( s1 == NULL ) {
				strcpy (address, "* ");
			}
			else {  
				s1 +=+strlen(left_string)+1;
				char* s2 = strstr(s1, right_string);
	//printf("s2 %s\n", s2);
				if ( s2 == NULL )
					strcpy (address, "* ");
				else {
					int len = s2-s1;
					strncpy (address, s1, len);
					if (address[len-1]==':')
						len--;
					address[len]='\0';
				}
			}		

			// print address
			printf("%-15s  ", address);	

			// stars count
			if ( strcmp(address, "* ") == 0)
				stars++;
			else 
				stars = 0;

			// reached?
			if ( strcmp(address, dest_addr ) == 0)
				reached_dest = 1;
		}			
		// CR
		printf(" \n");
	}
}

int NR_traceroute_udp ( ) {

	// getifaddres
	get_ifaddrs();

	// print intro
	printf("traceboxing from  %s  to  %s  \n", local_addr, dest_addr);


	// UDP not raw SOCKET
	sndsocku = socket(AF_INET, SOCK_DGRAM, 0);

	dstu.sin_family = AF_INET;
	dstu.sin_addr.s_addr=inet_addr(dest_addr);
	int dest_port = 0x829a;
	dstu.sin_port=htons(dest_port);


	// maybe better change to udpsock instead of using always sndsock
	if (sndsock < 0) {
            printf("ERROR opening send socket\n");
            return 1;
        }


	int sent;
	unsigned char datagram[100];
	memset(sent_datagram, 0, 4096);	
	int timedout;
	int stars = 0;
	int tr_udp_nr_row_stars = 1;
	int tr_udp_nr_max_stars = 3;
	int icmp_type_3= 0;
	int icmp_other_type = 0;

	
	// UDP not raw SOCKET continues	
	

	int on = 1; 
	
	if (!(setsockopt(sndsocku, SOL_IP, IP_RECVERR,(char*)&on, sizeof(on)))) {
    		;//printf("IP_RECVERR set successfully\n");
	} else {
    		printf("Error setting IP_RECVERR\n");
	}

	// print line 0
	printf("  0:  ");
	printf("%-15s  ", local_addr);
	printf("[Non Rooted Traceroute UDP]  ");
	printf("\n");


	int  ttl = 1;

	for ( int i= 1; (i<64) && (stars < tr_udp_nr_max_stars ) && (!icmp_type_3) && (!icmp_other_type); i++) {
		timedout = 0;
		ttl = i;		
		// print line i
		printf("%3d:  ", ttl);
		// set ttl	
		if (!(setsockopt(sndsocku, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)))) {
	    		;//printf("TTL set successfully %d\n", ttl);
		} else {
	    		printf("Error setting TTL\n");
		}
		// 
		//datagram[7] = ttl;
	
		for ( int j=0; j<repeat_tr_udp_nr; j++) {
			// sending
			if ( increase_port_tr_udp_nr != 0 )
				dstu.sin_port=htons(dest_port ++);
			else
				dstu.sin_port=htons(dest_port);
			sent   = sendto(sndsocku, datagram, 80, 0,  (const struct sockaddr *) &dstu , sizeof(struct sockaddr)  );
			if (sent <= 0)
				printf("Error! Send =%d\n", sent);

			//  Handle receving ICMP Errors  
			int return_status=-1;
			char buffer[4096];
			struct iovec iov;                       //  Data array  
			struct msghdr msg;                      //  Message header  
			struct cmsghdr *cmsg;                   //  Control related data  
			struct sock_extended_err *sock_err;     //  Struct describing the error   
			struct icmp icmph;                   //  ICMP header  
			struct sockaddr_in remote;              //  Our socket  
			int fd;

			    iov.iov_base = &icmph;
			    iov.iov_len = sizeof(icmph);
			    msg.msg_name = (void*)&remote;
			    msg.msg_namelen = sizeof(remote);
			    msg.msg_iov = &iov;
			    msg.msg_iovlen = 1;
			    msg.msg_flags = 0;
			    msg.msg_control = buffer;
			    msg.msg_controllen = sizeof(buffer);
			    //  Receiving errors flog is set  
			    struct timeval next;					
			    gettimeofday(&next, 0);
			    next.tv_sec = (next.tv_sec + 3);
		   	    next.tv_usec = 0;
			    while (1) {
				struct timeval now;
				struct timeval delta;
				long delta_us;
				int res;
				fd_set readfs, errorfs;

				gettimeofday(&now, 0);
				delta_us = (long)(next.tv_sec - now.tv_sec) * 1000000 +
					(long)(next.tv_usec - now.tv_usec);
				if (delta_us > 0) {
					/* continue waiting for timeout or data */
					delta.tv_sec = delta_us / 1000000;
					delta.tv_usec = delta_us % 1000000;

					FD_ZERO(&readfs);
					FD_ZERO(&errorfs);
					FD_SET(sndsocku, &readfs);
					FD_SET(sndsocku, &errorfs);
					//printf("%ld.%06ld: select %ldus\n", (long)now.tv_sec, (long)now.tv_usec, delta_us);
					res = select(sndsocku + 1, &readfs, 0, &errorfs, &delta);
					gettimeofday(&now, 0);
					//printf("%ld.%06ld: select returned: %d, %s\n", (long)now.tv_sec, (long)now.tv_usec, res, res < 0 ? strerror(1) : "success");
					if (res > 0) {
						if (FD_ISSET(sndsocku, &readfs)) {
							//printf("ready for reading\n"); 
							break;
						}
						if (FD_ISSET(sndsocku, &errorfs)) {
							//printf("has error\n");
							break;
						}

					}
				}
				else  { timedout = 1;
					break;
				}
			}	

			    return_status = recvmsg(sndsocku, &msg, MSG_ERRQUEUE);
			//printf("return_status errqueue %d\n", return_status);


			// received icmp
			    if (return_status > -1) {
			//printf(	"msg len %d \n", msg.msg_controllen);
			    //  Control messages are always accessed via some macros 
		      
			//sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg); 
			//			printf("ICMP err %d" , sock_err->ee_type);fflush(stdout);
			    for (cmsg = CMSG_FIRSTHDR(&msg);cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) 
			    {
				//  Ip level  
				if (cmsg->cmsg_level == SOL_IP)
				{
				    //  We received an error  
				    if (cmsg->cmsg_type == IP_RECVERR)
				    {
					//printf("We got IP_RECVERR message\n");
					sock_err =  (struct sock_extended_err*)CMSG_DATA(cmsg); 
					if (sock_err)
					{
					    //  We are intrested in ICMP errors  
					    if (sock_err->ee_origin == SO_EE_ORIGIN_ICMP) 
					    {
						// print address properly
						struct sockaddr_in * sa = (struct sockaddr_in *) SO_EE_OFFENDER(sock_err);
						printf("%-15s  ", inet_ntoa(sa->sin_addr));
						stars = 0;

						//  Show ICMP errors types  
						switch (sock_err->ee_type) 
						{
							case 11:
								;
								//printf("ICMP er r %d\n%d %d %d %d %d %d \n" , sock_err->ee_type, cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type, &cmsg->cmsg_len, &cmsg->cmsg_level, &cmsg->cmsg_type); fflush(stdout);
								/*
								unsigned char * sd =  ((& sock_err)) +1;
								for (int i= 0; i< 400; i++ ) {
									if (sd[i] != 0 )
									 printf("%02x ", sd[i]);
									else
										printf("   ");
								}
								*/
								// print address properly
								break;
							case 3:
								printf("[ICMP Destination Unreachable (%s)]  ", icmp_type3_by_code[sock_err->ee_code]);
								icmp_type_3 = 1;
								break;

							default:
								printf("[ICMP Type %d Code %d]  ", sock_err->ee_type, sock_err->ee_code);
								icmp_other_type = 1;

						}
					    }
					}
				    }
				} 
			    }
			    }
			else {	
				// received udp answer, not icmp
				return_status = recvfrom(sndsocku, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *) &dstu2, &dstu2len);		
				//printf("return_status recv %d\n", return_status);
				if (return_status > -1) {
					printf("%s  ", inet_ntoa(dstu2.sin_addr));
					stars = 0;
				}
			}
			
			// timeout check
			if ( timedout == 1 ) {
				printf("* ");
				stars++;
			}
			} 
		// print new line
		printf ("\n");
		}

}

int main(int argc, char *argv[]) {

	// save command
	this_command = argv[0];	
	
	char outbuff[10000];
	if ( argc >= 3 )
	if ( strcmp (argv[2], "-buffer" ) == 0){

		setbuf(stdout, outbuff);
	}
	
    // parse layer 3 parameter first
    // here prot3 = 4
    if (argc > 2) {
	for (int i = 2; i < argc; i++ ) {
		if ( strncmp (argv[i], "-6", 2 ) == 0 ) {
			prot3 = 6;
		}
		if ( (strncmp (argv[i], "--", 2 ) == 0 ) || ( prot3 == 6) ) {
			break;
		}
	}	
    }

    char* url = argv[1]; // URL or IP
    char url_or_ip [INET6_ADDRSTRLEN];
   
    // resolve url
    if ( hostname_to_ip(url, url_or_ip, prot3) == 1) {
		// printf ("Unable to resolve address.\n");
		return 1;
		// strcpy(url_or_ip, url);
	}
	 

    // save it to set dest addr in IP header
    strcpy (dest_addr, url_or_ip);

	int tbs = 1;
	int args_split[30];
	args_split[0]= 1;
	// test how many tracebox to do
	if (argc > 2) {
		for (int i = 2; i < argc; i++ ) {

			if ( strncmp (argv[i], "--", 2 ) == 0 ) {
				args_split[tbs] = i;
				tbs++;	
				
			}
		}
		
	}
	args_split[tbs] = argc;
	
	for ( int i = 0; i < tbs; i++ ) {
		reset_params();
		int single_tb_argc = args_split[i+1] - args_split[i];
		char * single_tb_argv = * (& argv) + args_split[i];
		// tb parameters
		parse_params( args_split[i+1] - args_split[i], * (& argv) + args_split[i] );
		// tb delay
		if ( delay != 0 )
			sleep(delay);
		common_tracebox_main(dest_addr);	
	}
	

	// AD LIBITUM ACK, to really DOWNLOAD a file
	if ( ack_ad_libitum == 1 ) {
		cst_ttl = 1;
		custom_mask_ip->ttl = 1;
		custom_ip->ttl = 255;
		tcp_header->tcphdr.syn=0;
		tcp_header->tcphdr.ack=1;
		keep_session = 1;
		int count=0;
		while (1) {
			common_tracebox_main(url_or_ip);	
			usleep(1000);
			count++;
			printf("COUNT %d\n", count);
		}

	}

	// undrop reset if setted before
	if ( dropped_rst == 1 ) {
		//popen("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP", "r");	
		//execve("/sbin/iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP", (char * const*) ipt_argv, envp);
		// changed because not handled correctly in JNI on Android
	}


	// time to return :)
	return 0;
}
