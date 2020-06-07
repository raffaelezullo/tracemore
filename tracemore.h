/*
Tracemore
RAFFAELE ZULLO
2020
*/

#include <asm/byteorder.h>
#include <stdbool.h>

#ifndef IPPROTO_ICMP
# define IPPROTO_ICMP            1
#endif
#ifndef IPPROTO_IP
# define IPPROTO_IP              0
#endif
#ifndef IPPROTO_TCP
# define IPPROTO_TCP             6
#endif
#ifndef IPPROTO_RAW
# define IPPROTO_RAW             255
#endif


#define DATAGRAM_SIZE            4096
#define ANSWER_TEXT_SIZE         10000

#define NI_MAXHOST      1025
#define NI_MAXSERV      32
#define NI_NUMERICHOST  1


struct my_icmphdr
{
  uint8_t type;                /* message type */
  uint8_t code;                /* type sub-code */
  uint16_t checksum;
  union
  {
    struct
    {
      uint16_t        id;
      uint16_t        sequence;
    } echo;                        /* echo datagram */
    uint32_t        gateway;        /* gateway address */
    struct
    {
      uint16_t        __glibc_reserved;
      uint16_t        mtu;
    } frag;                        /* path mtu discovery */
  } un;
};



struct my_ipv6_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8			priority:4,
				version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8			version:4,
				priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8			flow_lbl[3];

	__be16			payload_len;
	__u8			nexthdr;
	__u8			hop_limit;

	struct	in6_addr	saddr;
	struct	in6_addr	daddr;
};


// structs need for UDP trick
#define SO_EE_ORIGIN_NONE    0
#define SO_EE_ORIGIN_LOCAL   1
#define SO_EE_ORIGIN_ICMP    2
#define SO_EE_ORIGIN_ICMP6   3

struct sock_extended_err {
  uint32_t ee_errno;   // error number 
  uint8_t  ee_origin;  // where the error originated  
  uint8_t  ee_type;    // type  
  uint8_t  ee_code;    // code  
  uint8_t  ee_pad;
  uint32_t ee_info;    // additional information  
  uint32_t ee_data;    // other data  
  // More data may follow  
};
#define SO_EE_OFFENDER(ee)      ((struct sockaddr*)((ee)+1))
//


struct byte_by_bits {
uint8_t bit0: 1;
uint8_t bit1: 1;
uint8_t bit2: 1;
uint8_t bit3: 1;
uint8_t bit4: 1;
uint8_t bit5: 1;
uint8_t bit6: 1;
uint8_t bit7: 1;

};


// struct to resolve names to ip addresses

struct addrinfo {
       int              ai_flags;
       int              ai_family;
       int              ai_socktype;
       int              ai_protocol;
       socklen_t        ai_addrlen;
       struct sockaddr *ai_addr;
       char            *ai_canonname;
       struct addrinfo *ai_next;
};


// to parse Flags and Fragment Offeset in IP HEADER
struct new_iphdr {

  #if __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned int ihl:4;
  unsigned int version:4;
  #elif __BYTE_ORDER == __BIG_ENDIAN
  unsigned int version:4;
  unsigned int ihl:4;
  #else
  # error "Please fix <bits/endian.h>"
  #endif
  
  // new part starts here DSCP + ECN instead of TOS
  // u_int8_t tos;
  #  if __BYTE_ORDER == __LITTLE_ENDIAN 
  u_int8_t ecn : 2;
  u_int8_t dscp : 6;
  #  elif __BYTE_ORDER == __BIG_ENDIAN
  u_int8_t dscp : 6;
  u_int8_t ecn : 2;
  #else
  # error "Please fix <bits/endian.h>"
  #endif
  // end of new part

  u_int16_t tot_len;
  u_int16_t id;

  // new part starts here (flags + frag_off)
  //u_int16_t frag_off;
  #  if __BYTE_ORDER == __LITTLE_ENDIAN 
  uint16_t frag_off_5 : 5 ; 
  uint16_t mf  : 1 ;
  uint16_t df : 1 ;
  uint16_t res : 1 ;
  uint16_t frag_off_8 : 8;
  #  elif __BYTE_ORDER == __BIG_ENDIAN
  uint16_t res : 1 ;
  uint16_t df : 1 ;
  uint16_t mf  : 1 ;
  uint16_t frag_off_5 : 5 ;
  uint16_t frag_off_8 : 8 ;
  #else
  # error "Please fix <bits/endian.h>"
  #endif
  // end of new part

  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;


};


// to better parse priority and flow lbl
struct new_my_ipv6_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
  uint32_t    trafficclass_4_most:4,
        version:4,
        flow_lbl_4:4,
        trafficclass_4_less:4,
        flow_lbl_16:16;
                
#elif defined(__BIG_ENDIAN_BITFIELD)
  uint32_t    version:4,
        trafficclass_4_most:4,
        trafficclass_4_less:4,
        flow_lbl_4:4;
        flow_lbl_16:16;

#else
#error  "Please fix <asm/byteorder.h>"
#endif
  u_int16_t   payload_len;
  uint8_t     nexthdr;
  uint8_t     hop_limit;

  struct  in6_addr  saddr;
  struct  in6_addr  daddr;
int flow_lbl;
};

// helpfull methods for iphdr
int get_fragoff( struct new_iphdr * ip ) {
  return ip->frag_off_5 * 256 + ip->frag_off_8;
}

void set_fragoff( struct new_iphdr * ip,  int value ) {
  ip->frag_off_5 = value / 256;
  ip->frag_off_8 = value % 256;
}


// helpfull methods for my_ipv6_hdr
int get_trafficclass( struct new_my_ipv6_hdr * ip ) {
  return ip->trafficclass_4_most *16 + ip->trafficclass_4_less;
}

void set_trafficclass( struct new_my_ipv6_hdr * ip,  int value ) {
  ip->trafficclass_4_most = value / 16;
  ip->trafficclass_4_less = value % 16;
}

int get_trafficclass_ecn ( struct new_my_ipv6_hdr * ip ) {
  return get_trafficclass(ip) % 4;
}
void set_trafficclass_ecn ( struct new_my_ipv6_hdr * ip,  int value ) {
  int dscp = get_trafficclass_dscp(ip);
  int ecn = value;
  int tclass = dscp *4 + ecn;
  set_trafficclass(ip, tclass);
}

int get_trafficclass_dscp ( struct new_my_ipv6_hdr * ip ) {
  return get_trafficclass(ip) / 4;
}
void set_trafficclass_dscp( struct new_my_ipv6_hdr * ip,  int value ) {
  int dscp = value;
  int ecn = get_trafficclass_ecn(ip);;
  int tclass = dscp *4 + ecn;
  set_trafficclass(ip, tclass);
}


int get_flowlabel( struct new_my_ipv6_hdr * ip ) {
  return ip->flow_lbl_4 * 0x10000 + ip->flow_lbl_16;
}

void set_flowlabel( struct new_my_ipv6_hdr * ip, int value ) {
  ip->flow_lbl_4  = value / 0x10000;
  ip->flow_lbl_16 = value % 0x10000;
}



// to parse Res bits and NS flag in TCP HEADER
struct new_tcphdr {
  u_int16_t source;
  u_int16_t dest;
  u_int32_t seq;
  u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN 
  // doff-res1
    u_int16_t ns:1;
  u_int16_t res:3;
  u_int16_t doff:4;
  // res2-flags
  u_int16_t flags:6;
  u_int16_t ece:1;
  u_int16_t cwr:1;
#  elif __BYTE_ORDER == __BIG_ENDIAN
  // doff-res1
  u_int16_t doff:4;
  u_int16_t res:3;
    u_int16_t ns:1;
  // res2-flags
  u_int16_t cwr:1;
  u_int16_t ece:1;
  u_int16_t flags:6
# endif
  u_int16_t window;
  u_int16_t check;
  u_int16_t urg_ptr;
};


// structs needed out of BB
typedef struct len_and_sockaddr {
  socklen_t len;
  union {
    struct sockaddr sa;
    struct sockaddr_in sin;
#if ENABLE_FEATURE_IPV6
    struct sockaddr_in6 sin6;
#endif
  } u;
} len_and_sockaddr;
enum {
  LSA_LEN_SIZE = offsetof(len_and_sockaddr, u),
  LSA_SIZEOF_SA = sizeof(
    union {
      struct sockaddr sa;
      struct sockaddr_in sin;
#if ENABLE_FEATURE_IPV6
      struct sockaddr_in6 sin6;
#endif
    }
  )
};

enum {
  SIZEOF_ICMP_HDR = 8,
  rcvsock2 = 3, /* receive (icmp & tcp) socket file descriptor */
  sndsock2 = 4, /* send (tcp) socket file descriptor */
};

struct tcp_option_mss
{
    uint8_t kind;               /* 2 */
    uint8_t len;                /* 4 */
    uint16_t mss;
} __attribute__((packed));

struct tcp_option_sack_perm
{
    uint8_t kind;               /* 4 */  //RZ
    uint8_t len;                /* 2 */
}__attribute__((packed));

struct tcp_option_sack
{
    uint8_t kind;               /* 5 */
    uint8_t len;                /* variable, set to 10 */ //now set to 18
    // uint8_t sack_block[8];
  uint32_t start;
  uint32_t end;
}__attribute__((packed));


struct tcp_option_timestamp
{
    uint8_t kind;               /* 8 */
    uint8_t len;                /* 10 */
    uint32_t tsval;
    uint32_t tsecr;
    
}__attribute__((packed));

struct tcp_option_nop
{
    uint8_t kind;               /* 1 */
    
}__attribute__((packed));

struct tcp_option_windowscale
{
    uint8_t kind;               /* 3 */
    uint8_t len;                /* 3 */
    uint8_t value;
    
    
}__attribute__((packed));

struct tcp_option_mpcapable
{
    uint8_t kind;               /* 30 */
    uint8_t len;                /* 8 */
#if BYTE_ORDER == __LITTLE_ENDIAN
  u_int8_t  version:4,
      subtype:4;
#else /* BIG_ENDIAN */
  u_int8_t  subtype:4,
      version:4;    
#endif
  u_int8_t flags;
  u_int64_t key1;
  u_int64_t key2;
#define MPCAP_PROPOSAL_SBIT 0x01  /* SHA1 Algorithm */
#define MPCAP_HBIT    0x01  /* alias of MPCAP_PROPOSAL_SBIT */
#define MPCAP_GBIT    0x02  /* must be 0 */
#define MPCAP_FBIT    0x04  /* must be 0 */
#define MPCAP_EBIT    0x08  /* must be 0 */
#define MPCAP_DBIT    0x10  /* must be 0 */
#define MPCAP_CBIT    0x20  /* must be 0 */
#define MPCAP_BBIT    0x40  /* Extensibility bit, must be 0 */
#define MPCAP_ABIT    0x80  /* alias of MPCAP_CHECKSUM_CBIT */
#define MPCAP_CHECKSUM_CBIT 0x80  /* DSS Checksum bit */

}__attribute__((packed));

struct tcp_option_mpjoin {
  uint8_t kind;               // 30
  uint8_t len;                // 12
#if BYTE_ORDER == __LITTLE_ENDIAN
  u_int8_t  B:1,
      res:3,
      subtype:4;
#else // BIG_ENDIAN
  u_int8_t  subtype:4,
      res:3,
      B:1;
#endif
  uint8_t   address_id;
  uint32_t  B_token;
  uint32_t  A_random;
}__attribute__((packed));


struct mptcp_dss_copt {
  u_int8_t  mdss_kind;
  u_int8_t  mdss_len;
#if BYTE_ORDER == __LITTLE_ENDIAN
  u_int8_t  mdss_reserved1:4,
      mdss_subtype:4;
#else /* BIG_ENDIAN */
  u_int8_t  mdss_subtype:4,
      mdss_reserved1:4;
#endif
  u_int8_t  mdss_flags;
}__attribute__((__packed__));
/* 32-bit DSS option */
struct mptcp_dsn_opt {
  struct mptcp_dss_copt mdss_copt;
  u_int32_t mdss_dsn;   /* Data Sequence Number */
  u_int32_t mdss_subflow_seqn;  /* Relative Subflow Seq Num */
  u_int16_t mdss_data_len;    /* Data Length */
  u_int16_t mdss_xsum;    /* Data checksum - optional */

}__attribute__((__packed__));

struct tcp_option_fo
{
    uint8_t kind;
    uint8_t len;
    uint8_t cookie[16];
}__attribute__((packed));

struct tcp_option_fo2
{
    uint8_t kind;
    uint8_t len;
    uint8_t magic[2];
    uint8_t cookie[16];
}__attribute__((packed));

struct tcp_option
{
    uint8_t kind;               /* 3 */
    uint8_t len;                /* 3 */
    uint8_t value;
}__attribute__((packed));


struct tcphdr_mss
{
    struct tcphdr tcphdr; 
    
    /*
    struct tcp_option_mss mss;
    struct tcp_option_sack_perm sack_perm;
    struct tcp_option_sack sack;
    struct tcp_option_windowscale ws;
    struct tcp_option_mpcapable mpcapable;
    /*
    struct tcp_option_timestamp timestamp;
    struct tcp_option_nop nop;
    
   
    */
};

struct udp_opt_cco
{
    uint8_t   kind;               
    uint8_t   len ;               
    uint16_t  value;
}__attribute__((packed));


// Used to compute the TCP checksum
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};



// IP HEADER fields names
const char* ip_fields_names[] = {
 "IP::Version",
 "IP::HeaderLength",
 "IP::DSCP", /* 25 */
 "IP::ECN",
 "IP::TotalLength",
 "IP::ID",
 "IP::Flags",   
 "IP::FragmentOffset",  
 "IP::TTL",
 "IP::Protocol",
 "IP::Checksum",
 "IP::SourceAddr",
 "IP::DestAddr",
};

// UDP header fields names and lengths
#define UDP__SOURCE 0
#define UDP__DEST 1
#define UDP__LENGTH 2
#define UDP__CHECKSUM 3
const char* udp_fields_names[4] = {
 "UDP::SourcePort",     
 "UDP::DestPort",
 "UDP::Length",
 "UDP::Checksum",
};

const char* udp_fields_lengths[4] = {
2, // "UDP::SourcePort",     
2, // "UDP::DestPort",
2, // "UDP::Length",
2 // "UDP::Checksum",
};

// TCP header fields names
const char* tcp_fields_names[] = {
 "TCP::SourcePort",
 "TCP::DestPort",
 "TCP::SeqNumber",
 "TCP::AckNumber", 
 "TCP::Offset",
 "TCP::Reserved",
 "TCP::Flags",
 "TCP::Window",
 "TCP::Checksum",
 "TCP::UrgentPtr",
};

// ICMP constants
const char* icmp_type3_by_code[15] = {
"Net Unreachable",
"Host Unreachabe",
"Protocol Unreachable",
"Port Unreachable",
"Fragmentation Needed and Don't Fragment was Set",
"Source Route Failed",
"Destination Network Unknown",
"Destination Host Unknown",
"Source Host Isolated",
"Communication with Destination Network is Administratively Prohibited",
"Communication with Destination Host is Administratively Prohibited",
"Destination Network Unreachable for Type of Service",
"Destination Host Unreachable for Type of Service",
"Communication Administratively Prohibited!",
"Host Precedence Violation",
"Precedence cutoff in effect"
};


bool anydiff( char* a , char* b, int len) ;

bool any( char* a, int len) ;

void copy( char* a, char* b, int len) ; 

uint32_t mptcp_sha1hash (uint64_t u) ;

uint16_t flip_bytes_uint16t ( uint16_t u ) ;

int get_ifaddrs() ;

int create_raw_sockets() ;

int compare_in6_addr ( struct in6_addr  a, struct in6_addr b) ;

void set_in6_addr(struct in6_addr * a, uint32_t b[4]) ;

int copy_in6_addr ( struct in6_addr * a, struct in6_addr * b) ;

int compare_field ( char* sent, char* rec, char* mod, char* mask, int len) ;  

void store_field ( char* sent, char* rec, char* mod, char* mask, int len, int c) ;

char * rz_ntoa ( struct in_addr in ) ;

long  rand_long_int () ;

void parse_custom_value ( char* value, int* val, int* def ) ; 

static len_and_sockaddr* dup_sockaddr(const len_and_sockaddr *lsa) ;

static uint16_t ip_checksum(void* vdata,size_t length) ;

static unsigned short csum(unsigned short *buf, int nwords) ;

static struct iphdr * castToIP(char datagram[], int offset) ;    

static struct icmp * castToICMP(char datagram[], int offset) ;

static struct tcphdr * castToTCP(char datagram[], int offset) ;

static uint16_t transport_checksum(const void *buff, size_t len, in_addr_t src_addr,  in_addr_t  dest_addr) ;

static uint16_t transport_checksum_custom (const void *buff, size_t len, size_t ph_len, in_addr_t src_addr,  in_addr_t  dest_addr) ;

static uint16_t transport_checksum6(const void *buff, size_t len, struct in6_addr src_addr, struct in6_addr dest_addr) ;

static uint16_t transport_checksum_custom6(const void *buff, size_t len, size_t ph_len, struct in6_addr src_addr, struct in6_addr dest_addr) ;

void check_checksum (unsigned char * sent, int s_offset, unsigned char * rec, int r_offset, int len, int sentlen, unsigned char* mod, char* mask) ;

void set_default_tcp(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) ;

void set_default_udp(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) ;

void set_default_icmp(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) ;  

void set_default_ip6(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) ;

void set_default_ip(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) ;

void reset_chksumwrg() ;

void reset_single_tb_params() ;

void reset_multi_tb_params() ;

void reset_tb_params() ;

void reset_ip_params() ;

void reset_udp_params() ;

void reset_tcp_params() ;

void reset_params() ;

void parse_tr_udp_nr_params( int c, char* v[]) ;

void parse_tr_ping_nr_params( int c, char* v[]) ;  

void parse_se_params (int c, char * v[]) ;

void parse_nr_params (int c, char * v[]) ;

void parse_tb_params( int c, char* v[]) ;

void parse_ip6_params( int c, char* v[]) ;

void parse_ip_params( int c, char* v[]) ;

void parse_otherprot4_params(c, v) ;

void parse_icmp_params( int c, char* v[]) ;

void parse_udp_params( int c, char* v[]) ;

void parse_tcp_params( int c, char* v[]) ;

void parse_tcp_options_params( int c, char* v[]) ;

void parse_payload_params( int c, char* v[])  ;

void parse_post_payload_tcp_params( int c, char* v[]) ;

void parse_post_payload_udp_params( int c, char* v[]) ;

void parse_params( int c, char* v[]) ;

int set_default_fields(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) ;

void set_field ( char* field, char* value) ;

int set_custom_fields (char datagram[], int seq, int ttl, int syn_flag, int rst_flag) ;

static int  send_probe(char datagram[], int seq, int ttl, int syn_flag, int rst_flag) ; 

int wait_for_reply_tcp(int sck, len_and_sockaddr *from_lsa, struct sockaddr *to, unsigned *timestamp_us, int *left_ms) ;

static int wait_for_reply(int sck, len_and_sockaddr *from_lsa, struct sockaddr *to, unsigned *timestamp_us, int *left_ms, int*  which_sock) ;

static int packet_ok(int read_len, len_and_sockaddr *from_lsa, struct sockaddr *to, int seq) ;

static void print_delta_ms(unsigned t1p, unsigned t2p);

void compare_packets_default(unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) ;

void compare_ip6_packets_default(unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) ;

void compare_ip_packets_default(unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) ;

void compare_tcp_packets_default (unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) ;

void compare_tcp_packets_default (unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) ;

void compare_tcp_options_default (unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) ;

void compare_udp_packets_default (unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) ;

void compare_icmp_packets_default (unsigned char* sent_, int s_offset , unsigned char* def_ , int d_offset ) ;

static void compare_ip6_packets (unsigned char * sent_, int s_offset, unsigned char * rec_, int r_offset, int len, unsigned char* mod_, char* mask_, int ttl) ;

static void compare_ip_packets (unsigned char * sent, int s_offset, unsigned char * rec, int r_offset, int len, unsigned char* mod, char* mask, int ttl) ;

static void compare_udp_packets (unsigned char * sent, int s_offset, unsigned char * rec, int r_offset, int len, int sentlen, unsigned char* mod, char* mask)  ;

void print_pkt (unsigned char * pkt, int len) ;

void print_pkt_hex (unsigned char * pkt, int len) ;

void print_pkt_text (unsigned char * pkt, int len) ;

void print_ip_addr (uint32_t*  addr) ;
