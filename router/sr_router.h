/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

#define DEST_NET_UNREACHABLE   1
#define DEST_HOST_UNREACHABLE  2
#define PORT_UNREACHABLE       3
#define TTL_EXCEEDED           4

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
void handle_arp_request(struct sr_instance* sr, struct sr_arpreq* req);
int validate(uint8_t* buf, uint32_t len);
struct sr_rt* check_rt(struct sr_instance *sr, uint32_t dip);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );
void send_icmp_reply(struct sr_instance* sr,
            uint32_t sip,
            uint32_t dip,
            uint8_t smac[ETHER_ADDR_LEN],
            uint8_t dmac[ETHER_ADDR_LEN],
            uint16_t ip_id,
            uint32_t icmp_unused,
            uint8_t *icmp_data,
            uint16_t icmp_data_len,
            struct sr_rt* rt);
void send_icmp_exception(struct sr_instance* sr,
            uint32_t dip,
            uint8_t dmac[ETHER_ADDR_LEN],
            uint16_t ip_id,
            uint8_t *icmp_data,
            uint16_t icmp_data_len,
            uint8_t icmp_exeption_type);
void foward_ip_packet(struct sr_instance* sr, 
                uint8_t* packet, 
                unsigned int len, 
                struct sr_rt* rt, 
                struct sr_arpentry* entry);
void handle_arp_request(struct sr_instance* sr, struct sr_arpreq* req);
void send_icmp_exception_all_packet(struct sr_instance* sr, struct sr_packet* packet);
void send_arp_request(struct sr_instance* sr, uint32_t dip, struct sr_rt* rt);
#endif /* SR_ROUTER_H */
