/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>



#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

int validate(uint8_t* buf, uint32_t len) 
{
    uint32_t minlength = sizeof(sr_ethernet_hdr_t);
    if (len < minlength) 
    {
        fprintf(stderr, "Failed to validate ETHERNET header: insufficient length.\n");
        return 0;
    }

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buf;
    if (eth_hdr->ether_type == htons(ethertype_ip)) 
    { /* IP */
        minlength += sizeof(sr_ip_hdr_t);
        if (len < minlength) 
        {
            fprintf(stderr, "Failed to validate IP header: insufficient length.\n");
            return 0;
        }
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
        if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != 0xFFFF) 
        {
            fprintf(stderr, "Failed to validate IP header: incorrect checksum.\n");
            return 0;
        }
        if (ip_hdr->ip_p == ip_protocol_icmp) 
        { /* ICMP */
            minlength += sizeof(sr_icmp_hdr_t);
            if (len < minlength) 
            {
                fprintf(stderr, "Failed to validate ICMP header: insufficient length\n");
                return 0;
            }
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            if (cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)) != 0xFFFF) 
            {
                fprintf(stderr, "Failed to validate ICMP header: incorrect checksum.\n");
                return 0;
            }
        }
    } 
    else if (eth_hdr->ether_type == htons(ethertype_arp)) 
    { /* ARP */
        minlength += sizeof(sr_arp_hdr_t);
        if (len < minlength) 
        {
            fprintf(stderr, "Failed to print ARP header, insufficient length\n");
            return 0;
        }
    } else 
    {
        fprintf(stderr, "Unrecognized Ethernet Type: %u\n", htons(eth_hdr->ether_type));
        return 0;
    }
    return 1; 
}

struct sr_rt* check_rt(struct sr_instance *sr, uint32_t dip)
{
    struct sr_rt* rt;
    rt = sr_longest_prefix_match(sr, dip);
    return rt;
}
/*
int send_packet(struct sr_instance *sr, uint32_t dip, uint8_t* packet, unsigned int len)
{
    struct sr_rt* rt;
    rt = sr_longest_prefix_match(sr, dip);

    if(rt == NULL)
    {
        return DEST_NET_UNREACHABLE;
    }
    sr_send_packet(sr, packet, len, rt->interface);
    return 0;
}
*/
void send_icmp_reply(struct sr_instance* sr,
            uint32_t sip,
            uint32_t dip,
            uint8_t smac[ETHER_ADDR_LEN],
            uint8_t dmac[ETHER_ADDR_LEN],
            uint16_t ip_id,
            uint32_t icmp_unused,
            uint8_t *icmp_data,
            uint16_t icmp_data_len,
            struct sr_rt* rt)
{
    /*create icmp_packet*/

    sr_icmp_hdr_t* icmp_packet;
    uint32_t icmp_len = sizeof(sr_icmp_hdr_t) + icmp_data_len;
    icmp_packet = (sr_icmp_hdr_t*)malloc(icmp_len);
    icmp_packet->icmp_type = 0;
    icmp_packet->icmp_code = 0;
    icmp_packet->unused = icmp_unused;
    memcpy((uint8_t*)icmp_packet + sizeof(sr_icmp_hdr_t), icmp_data, icmp_data_len);
    icmp_packet->icmp_sum = 0;    
    icmp_packet->icmp_sum = cksum(icmp_packet, icmp_len);
    
    /*create ip_header*/
    sr_ip_hdr_t* ip_packet;
    ip_packet = (sr_ip_hdr_t*)malloc(sizeof(sr_ip_hdr_t));
    ip_packet->ip_v = 4;
    ip_packet->ip_hl = 5; /*minimum 5 words*/
    ip_packet->ip_tos = 0;
    ip_packet->ip_len = htons(icmp_len + sizeof(sr_ip_hdr_t));
    ip_packet->ip_id = htons(ip_id);
    ip_packet->ip_off = htons(IP_DF);
    ip_packet->ip_ttl = 64;
    ip_packet->ip_p = ip_protocol_icmp;
    ip_packet->ip_src = sip;
    ip_packet->ip_dst = dip;
    ip_packet->ip_sum = 0;
    ip_packet->ip_sum = cksum(ip_packet, sizeof(sr_ip_hdr_t));

    /*create ethernet_header*/
    sr_ethernet_hdr_t* ether_packet;
    ether_packet = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
    memcpy(ether_packet->ether_dhost, dmac, ETHER_ADDR_LEN);
    memcpy(ether_packet->ether_shost, smac, ETHER_ADDR_LEN);
    ether_packet->ether_type = htons(ethertype_ip);

    /*create packet*/
    uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len;
    uint8_t* packet = malloc(len);
    memcpy(packet, ether_packet, sizeof(sr_ethernet_hdr_t));
    memcpy(packet + sizeof(sr_ethernet_hdr_t), ip_packet, sizeof(sr_ip_hdr_t));
    memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_packet, icmp_len);

    sr_send_packet(sr, packet, len, rt->interface);

    fprintf(stderr, "send icmp reply \nSource:  ");
    print_addr_ip_int(ntohl(ip_packet->ip_src));
    fprintf(stderr, "Target: ");
    print_addr_ip_int(ntohl(ip_packet->ip_dst));



    free(icmp_packet);
    free(ip_packet);
    free(ether_packet);
    free(packet);

    return;
}

void send_icmp_exception(struct sr_instance* sr,
            uint32_t dip,
            uint8_t dmac[ETHER_ADDR_LEN],
            uint16_t ip_id,
            uint8_t *icmp_data,
            uint16_t icmp_data_len,
            uint8_t icmp_exeption_type)
{


    sr_icmp_hdr_t* icmp_packet;
    uint32_t icmp_len = icmp_data_len + sizeof(sr_icmp_hdr_t);
    icmp_packet = malloc(icmp_len);

    if(icmp_exeption_type == PORT_UNREACHABLE)
    {
        icmp_packet->icmp_type = 3;
        icmp_packet->icmp_code = 3;
    }
    else if(icmp_exeption_type == DEST_NET_UNREACHABLE)
    {
        icmp_packet->icmp_type = 3;
        icmp_packet->icmp_code = 0;        
    }
    else if(icmp_exeption_type == DEST_HOST_UNREACHABLE)
    {
        icmp_packet->icmp_type = 3;
        icmp_packet->icmp_code = 1;
    }
    else if(icmp_exeption_type == TTL_EXCEEDED)
    {
        icmp_packet->icmp_type = 11;
        icmp_packet->icmp_code = 0;

    }
    memcpy((uint8_t*)icmp_packet + sizeof(sr_icmp_hdr_t), icmp_data, icmp_data_len);
    icmp_packet->icmp_sum = 0;    
    icmp_packet->icmp_sum = cksum(icmp_packet, icmp_len);
    icmp_packet->unused = 0;

    /*create ip_header*/
    struct sr_rt* rt = check_rt(sr, dip);
    struct sr_if* interf = sr_get_interface(sr, rt->interface);

    sr_ip_hdr_t* ip_packet;
    ip_packet = (sr_ip_hdr_t*)malloc(sizeof(sr_ip_hdr_t));

    ip_packet->ip_v = 4;
    ip_packet->ip_hl = 5;/*minimum 5 words*/
    ip_packet->ip_tos = 0;
    ip_packet->ip_len = htons(icmp_len + sizeof(sr_ip_hdr_t));
    ip_packet->ip_id = htons(ip_id);
    ip_packet->ip_off = htons(IP_DF);
    ip_packet->ip_ttl = 4;
    ip_packet->ip_p = ip_protocol_icmp;
    ip_packet->ip_src = interf->ip;
    ip_packet->ip_dst = dip;
    ip_packet->ip_sum = 0;
    ip_packet->ip_sum = cksum(ip_packet, sizeof(sr_ip_hdr_t));

    /*create ethernet_header*/
    sr_ethernet_hdr_t* ether_packet;
    ether_packet = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
    memcpy(ether_packet->ether_dhost, dmac, ETHER_ADDR_LEN);
    memcpy(ether_packet->ether_shost, interf->addr, ETHER_ADDR_LEN);
    ether_packet->ether_type = htons(ethertype_ip);

    fprintf(stderr, " Source : ");
    print_addr_eth(ether_packet->ether_shost);
    fprintf(stderr, " Target: ");
    print_addr_eth(ether_packet->ether_dhost);
    fprintf(stderr, "\n");

    /*create packet*/
    uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len;
    uint8_t* packet = malloc(len);
    memcpy(packet, ether_packet, sizeof(sr_ethernet_hdr_t));
    memcpy(packet + sizeof(sr_ethernet_hdr_t), ip_packet, sizeof(sr_ip_hdr_t));
    memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_packet, icmp_len);


    sr_send_packet(sr, packet, len, rt->interface);

    free(icmp_packet);
    free(ip_packet);
    free(ether_packet);
    free(packet);

    return;

}

void foward_ip_packet(struct sr_instance* sr, 
                uint8_t* packet, 
                unsigned int len, 
                struct sr_rt* rt, 
                struct sr_arpentry* entry)
{
    uint8_t* buf = malloc(len);
    memcpy(buf, packet, len);
    sr_ethernet_hdr_t* ether_hdr;
    ether_hdr = (sr_ethernet_hdr_t*)buf;

    sr_ip_hdr_t* ip_hdr; 
    ip_hdr = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t)); 

    if(ip_hdr->ip_ttl == 1) /* send icmp exception TTL_EXCEEDED*/
    {
        send_icmp_exception(sr,
                    ip_hdr->ip_src,
                    ether_hdr->ether_shost,
                    htons(ip_hdr->ip_id) + 1,
                    buf + sizeof(sr_ethernet_hdr_t),
                    htons(ip_hdr->ip_len),
                    TTL_EXCEEDED);
        return;
    }

    struct sr_if* interf = sr_get_interface(sr, rt->interface);
    memcpy(ether_hdr->ether_shost, interf->addr, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);

    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    sr_send_packet(sr, buf, len, rt->interface);
    free(buf);
}


void handle_arp_request(struct sr_instance* sr, struct sr_arpreq* req)
{
    time_t now = time(NULL);
    if(difftime(now, req->sent) > 0.99)
    {
        if(req->times_sent >=5)
        {
            /*send host unreachable to all packet*/
            send_icmp_exception_all_packet(sr, req->packets);
            sr_arpreq_destroy(&sr->cache, req);
        }
        else 
        {
            struct sr_rt* rt;
            rt = check_rt(sr, req->ip);
            if(rt)
            {
                send_arp_request(sr, req->ip, rt);    
            }
            else
            {     /*send host unreachable  */
                fprintf(stderr, "send host unreachable, ip is not found in rt \n ");
                struct sr_packet* pac;
                pac = req->packets;
                while(pac->next != NULL)
                {
                    
                    sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*)(pac->buf);
                    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(pac->buf + sizeof(sr_ethernet_hdr_t));
                    send_icmp_exception(sr,
                                    ip_hdr->ip_src,
                                    ether_hdr->ether_shost,
                                    ntohs(ip_hdr->ip_id) + 1,
                                    pac->buf + sizeof(sr_ethernet_hdr_t),
                                    ntohl(ip_hdr->ip_len),
                                    DEST_HOST_UNREACHABLE);    
                }             
                
            }
            req->sent = now;
            req->times_sent++;
        }
    }
}

void send_icmp_exception_all_packet(struct sr_instance* sr, struct sr_packet* packet)
{   
    while(packet->next != NULL)
    {
        sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*)(packet->buf);
        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet->buf + sizeof(sr_ethernet_hdr_t));
        send_icmp_exception(sr,
                        ip_hdr->ip_src, 
                        ether_hdr->ether_shost,
                        ntohs(ip_hdr->ip_id) + 1,
                        packet->buf + sizeof(sr_ethernet_hdr_t),
                        ntohl(ip_hdr->ip_len),
                        DEST_HOST_UNREACHABLE);
        packet = packet->next;
    }
}


void send_arp_request(struct sr_instance* sr, uint32_t dip, struct sr_rt* rt)
{
    struct sr_if* interf = sr_get_interface(sr, rt->interface);

    sr_arp_hdr_t* arp_packet;
    arp_packet = (sr_arp_hdr_t*)malloc(sizeof(sr_arp_hdr_t));
    arp_packet->ar_hrd = htons(arp_hrd_ethernet);
    arp_packet->ar_pro = htons(0x0800);
    arp_packet->ar_hln = 6;
    arp_packet->ar_pln = 4;
    arp_packet->ar_op = htons(arp_op_request);
    memcpy(arp_packet->ar_sha, interf->addr, ETHER_ADDR_LEN);
    arp_packet->ar_sip = interf->ip;
    /*ignore arp_packet->ar_tha*/
    arp_packet->ar_tip = dip;

    /*create ethernet_header*/
    sr_ethernet_hdr_t* ether_packet;
    ether_packet = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
    memset(ether_packet->ether_dhost, 0xffffff, ETHER_ADDR_LEN);
    memcpy(ether_packet->ether_shost, interf->addr, ETHER_ADDR_LEN);
    ether_packet->ether_type = htons(ethertype_arp);

    /*  create buf*/
    uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* buf = (uint8_t*)malloc(len);
    memcpy(buf, ether_packet, sizeof(sr_ethernet_hdr_t));
    memcpy(buf + sizeof(sr_ethernet_hdr_t), arp_packet, sizeof(sr_arp_hdr_t));

    sr_send_packet(sr, buf, len, rt->interface);

    fprintf(stderr, "Send arp request, Source IP:  ");
    print_addr_ip_int(ntohl(arp_packet->ar_sip));
    fprintf(stderr, "Target:  ");
    print_addr_ip_int(ntohl(arp_packet->ar_tip));
    fprintf(stderr, "\n"); 
    free(arp_packet);
    free(ether_packet);
    free(buf);
}


void send_arp_reply(struct sr_instance* sr, 
                uint8_t smac[ETHER_ADDR_LEN],
                uint8_t dmac[ETHER_ADDR_LEN],
                uint32_t sip, 
                uint32_t dip,
                struct sr_rt* rt)
{

    sr_arp_hdr_t* arp_packet;
    arp_packet = (sr_arp_hdr_t*)malloc(sizeof(sr_arp_hdr_t));
    arp_packet->ar_hrd = htons(arp_hrd_ethernet);
    arp_packet->ar_pro = htons(0x0800);
    arp_packet->ar_hln = ETHER_ADDR_LEN;
    arp_packet->ar_pln = 4;
    arp_packet->ar_op = htons(arp_op_reply);    
    memcpy(arp_packet->ar_sha, smac, ETHER_ADDR_LEN);
    arp_packet->ar_sip = sip;
    memcpy(arp_packet->ar_tha, dmac, ETHER_ADDR_LEN);
    arp_packet->ar_tip = dip;

    

    /*create ethernet_header*/
    sr_ethernet_hdr_t* ether_packet;
    ether_packet = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
    memcpy(ether_packet->ether_dhost, dmac, ETHER_ADDR_LEN);
    memcpy(ether_packet->ether_shost, smac, ETHER_ADDR_LEN);
    ether_packet->ether_type = htons(ethertype_arp);

    fprintf(stderr, "sent arp reply, Source : ");
    print_addr_eth(ether_packet->ether_shost);
    fprintf(stderr, " Target: ");
    print_addr_eth(ether_packet->ether_dhost);
    fprintf(stderr, ")\n");

    struct sr_if* interf = sr_get_interface(sr, rt->interface);
    fprintf(stderr, "Interface Source : ");
    print_addr_eth(interf->addr);

    /*  create buf*/
    uint32_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* buf = (uint8_t*)malloc(len);
    memcpy(buf, ether_packet, sizeof(sr_ethernet_hdr_t));
    memcpy(buf + sizeof(sr_ethernet_hdr_t), arp_packet, sizeof(sr_arp_hdr_t));

    sr_send_packet(sr, buf, len, rt->interface);

    free(arp_packet);
    free(ether_packet);
    free(buf);
}

void send_all_packet(struct sr_instance* sr, struct sr_packet* packet)
{
    while(packet != NULL)
    {   
        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet->buf + sizeof(sr_ethernet_hdr_t));
        struct sr_rt* rt = check_rt(sr, ip_hdr->ip_dst);
        if(rt != NULL)
        {
            struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);/*check arpcache*/
            if (entry != NULL)
            {
                fprintf(stderr, "found entry in arpcache, send all packet ");

                foward_ip_packet(sr, packet->buf, packet->len, rt, entry);
                free(entry);
            }        
        }
        packet = packet->next;
    }
}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  /* fill in code here */
    struct sr_rt* rt;
    if (validate(packet, len) == 0) 
    {
        return;
    }

    sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*)packet;

    if (ether_hdr->ether_type == htons(ethertype_ip)) /* IP packet */
    {
        printf("Receive IP packet\n");
        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

        /*check interface*/
        struct sr_if* interf = sr->if_list;
        for(; interf != NULL; interf = interf->next)
        {
            if(interf->ip == ip_hdr->ip_dst)/*send ip packet to me*/
            {
  
                fprintf(stderr, "received IP packet, sent to me. Source: ");
                print_addr_ip_int(ntohl(ip_hdr->ip_src));
                fprintf(stderr, " Dest: ");
                print_addr_ip_int(ntohl(ip_hdr->ip_dst));

                sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                if(ip_hdr->ip_p == ip_protocol_icmp)/*received ICMP (type 0, code 0)*/
                {
                    fprintf(stderr, "received ICMP packet. ");
                    if (icmp_hdr->icmp_type !=8) /*check if it is ICMP echo request*/
                    {
                        return;
                    }
                    rt = check_rt(sr, ip_hdr->ip_src); 
                    if (rt != NULL)
                    {
                        send_icmp_reply(sr, 
                            ip_hdr->ip_dst,
                            ip_hdr->ip_src,
                            ether_hdr->ether_dhost,
                            ether_hdr->ether_shost,
                            htons(ip_hdr->ip_id) + 1,
                            icmp_hdr->unused,
                            packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t),
                            htons(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t),
                            rt);
                    }
                    
                }
                else/* tcp/udp packet, send icmp port unreachable (type 3, code 3)*/
                {
                    
                    rt = check_rt(sr, ip_hdr->ip_src); 
                    if(rt != NULL)
                    {
                        send_icmp_exception(sr,
                            ip_hdr->ip_src,
                            ether_hdr->ether_shost,
                            htons(ip_hdr->ip_id) + 1,
                            packet + sizeof(sr_ethernet_hdr_t),
                            htons(ip_hdr->ip_len),
                            PORT_UNREACHABLE);
                    }
                    
                }
                return;
            }
        }
            
        /*not to me, check routing table.*/           
        fprintf(stderr, "received IP packet, not sent to me. Source: ");
        print_addr_ip_int(ntohl(ip_hdr->ip_src));
        fprintf(stderr, " Dest: ");
        print_addr_ip_int(ntohl(ip_hdr->ip_dst));
        rt = check_rt(sr, ip_hdr->ip_dst); /*check_rt() return rt if match, NULL if miss*/
        if(rt != NULL) 
        {
            sr_print_routing_entry(rt);
            struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);/*check arpcache*/
            if (entry != NULL)
            {
                fprintf(stderr, "foward ip packet \n ");
                foward_ip_packet(sr, packet, len, rt, entry);
                free(entry);
            }
            else if (entry == NULL)
            {
                /*insert packet to arpqueue*/
                fprintf(stderr, "MAC not found in cache, insert packet to arpqueue \n ");
                struct sr_arpreq* req;
                req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, rt->interface);
                handle_arp_request(sr,req);
            }
            
        } 
        else 
        {
            fprintf(stderr,"no match");
            /*send icmp des net unreachable.(type 3, code 0)*/
            fprintf(stderr, " send icmp packet(DEST NET UNREACHABLE");
            send_icmp_exception(sr,
                    ip_hdr->ip_src,
                    ether_hdr->ether_shost,
                    htons(ip_hdr->ip_id) + 1,
                    packet + sizeof(sr_ethernet_hdr_t),
                    htons(ip_hdr->ip_len),
                    DEST_NET_UNREACHABLE);
        }
    
        
    }
    else if(ether_hdr->ether_type == htons(ethertype_arp)) /*ARP packet*/
    {
        sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

        struct sr_if* interf = sr->if_list;
        

        for(; interf != NULL; interf = interf->next)
        {
            if(interf->ip == arp_hdr->ar_tip)/* arp packet sent to me*/
            {
                 
                if(arp_hdr->ar_op == htons(arp_op_reply))/* arp reply to me*/
                {
                    fprintf(stderr, "Received ARP reply packet (Source: ");
                    print_addr_ip_int(ntohl(arp_hdr->ar_sip));
                    fprintf(stderr, " Target: ");
                    print_addr_ip_int(ntohl(arp_hdr->ar_tip));
                    fprintf(stderr, "\n"); 
                    struct sr_arpreq* req;
                    req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
                    
                    sr_arpcache_dump(&sr->cache);
                    if(req)
                    {
                        fprintf(stderr, "Insert MAC and ip successfully, send all packet with ip in paket arpqueue ");
                        send_all_packet(sr,req->packets);
                        sr_arpreq_destroy(&sr->cache, req);
                    } 
                } else if(arp_hdr->ar_op == htons(arp_op_request))/*arp request to me*/
                {
                    fprintf(stderr, "Received ARP request (Source: ");
                    print_addr_ip_int(ntohl(arp_hdr->ar_sip));
                    fprintf(stderr, " Target: ");
                    print_addr_ip_int(ntohl(arp_hdr->ar_tip));
                    fprintf(stderr, "\n");
                    fprintf(stderr, "xxxxx\n");
                    struct sr_rt* rt = check_rt(sr, arp_hdr->ar_sip);
                    if(rt != NULL)
                    {
                        send_arp_reply(sr, interf->addr, arp_hdr->ar_sha, arp_hdr->ar_tip, arp_hdr->ar_sip, rt);    
                    }
                }
                return;
            }
        }
    /*send_packet(sr, arp_hdr->ar_tip, packet, len);*/
    }
}
/* end sr_ForwardPacket */

