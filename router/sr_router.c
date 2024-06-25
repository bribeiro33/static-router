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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#ifndef SR_DEBUG_H
#define SR_DEBUG_H

#define DEBUG true

#endif // SR_DEBUG_H


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
    #if DEBUG
        print_hdrs(packet, len);
    #endif

    assert(sr && packet && interface);

    if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "Packet too short for Ethernet header\n");
        return;
    }

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    uint16_t ether_type = ntohs(eth_hdr->ether_type);

    if (ether_type == ethertype_ip) { // Handle IP Packet
        sr_handle_ip_packet(sr, packet, len, interface);
    } else if (ether_type == ethertype_arp) { // Handle ARP Packet
        sr_handle_arp_packet(sr, packet, len, interface);
    } else {
        fprintf(stderr, "unknown Ethernet type: %x\n", ether_type);
    }
} /* end sr_ForwardPacket */

void sr_handle_ip_packet(struct sr_instance* sr, uint8_t *pkt, unsigned int len, char* iface_name) {
    // get headers
    //sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)pkt;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) { // verify pkt len
        fprintf(stderr, "packet too short for IP header\n");
        return;
    }
    
    /* validate checksum */
    uint16_t recv_checksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint16_t calc_checksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
    if (recv_checksum != calc_checksum) {
        fprintf(stderr, "IP checksum error\n");
        return; // dropped
    }
    
    /* handle TTL */
    if (ip_hdr->ip_ttl <= 1) {
        // send ICMP time exceeded
        send_icmp_message(sr, pkt, 11, 0, len, sr_get_interface(sr, iface_name));
        return;
    }

    /* check if the packet is intended for this interface */
    struct sr_if* interface = sr_get_interface(sr, iface_name);
    // if dest ip (in hdr of incoming pkt) matches ip of any of the rtr ifaces,
    // pkt meant for router (no routing)
    struct sr_if *iface_list = sr->if_list;
    while (iface_list){
        if (iface_list->ip == ip_hdr->ip_dst) {
            // does incoming pkt use icmp protocol check
            if (ip_hdr->ip_p == ip_protocol_icmp) {
                sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t) + ip_hdr->ip_hl * 4);
                if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {  // echo request type
                    send_icmp_message(sr, pkt, 0, 0, len, interface);  // echo reply
                }
            }
            //If the packet contains a TCP or UDP payload, send an ICMP port unreachable to the sending host.
            else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
                send_icmp_message(sr, pkt, 3, 3, len, interface); // port unreachable
            }
            return; // stop processing since the packet has acheived its final dest (dropped if not one of conditions abv)
        }
        iface_list = iface_list->next;
    }

    /* forward packet */
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4); // recompute checksum
    forward_ip_packet(sr, pkt, len, ip_hdr, iface_name);
}


void sr_handle_arp_packet(struct sr_instance* sr, uint8_t *pkt, unsigned int len, char* iface_name) {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        fprintf(stderr, "Packet too short for ARP header\n");
        return;
    }
    // get arp header
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
    struct sr_if* interface = sr_get_interface(sr, iface_name);

    switch (ntohs(arp_hdr->ar_op)) {
        case arp_op_request:
            // if the arp req is for one of the router's interfaces
            if (arp_hdr->ar_tip == interface->ip) {
                // send reply
                send_arp_reply(sr, arp_hdr, interface);
            }
            break;
        case arp_op_reply:
            // cache replied MAC address and notify possibly waiting packets
            sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
            break;
        default:
            fprintf(stderr, "Unknown ARP opcode\n");
            break;
    }
}

void forward_ip_packet(struct sr_instance* sr, uint8_t* pkt, unsigned int len, sr_ip_hdr_t* ip_hdr, char* iface_name) {
    struct sr_rt* routing_entry = sr_find_longest_prefix_match(sr, ip_hdr->ip_dst);
    if (!routing_entry) {
        fprintf(stderr, "No routing entry found for destination IP\n");
        // dest net unreachable
        send_icmp_message(sr, pkt, 3, 0, len, sr_get_interface(sr, iface_name)); 
        return;
    }

    struct sr_if* out_iface = sr_get_interface(sr, routing_entry->interface);
    if (!out_iface) {
        fprintf(stderr, "Outgoing interface not found\n");
        return;
    }

    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, routing_entry->gw.s_addr);
    if (arp_entry) {
        // MAC address is known --> send packet
        send_packet_to_next_hop(sr, pkt, len, ip_hdr, out_iface, arp_entry->mac);
        free(arp_entry);
    } else {
        // MAC address is unknown --> queue the packet
        sr_arpcache_queuereq(&sr->cache, routing_entry->gw.s_addr, pkt, len, out_iface->name);
    }
}

struct sr_rt* sr_find_longest_prefix_match(struct sr_instance* sr, uint32_t dest_ip) {
    struct sr_rt* longest_match = NULL;
    struct sr_rt* rt_walker = sr->routing_table;
    int longest_len = -1;  // len of longest prefix match found

    while (rt_walker) {
        // check if the masked dest IP matches the masked entry IP
        if ((dest_ip & rt_walker->mask.s_addr) == (rt_walker->dest.s_addr & rt_walker->mask.s_addr)) {
            // calc the number of bits set in the netmask
            int match_len = __builtin_popcount(rt_walker->mask.s_addr);
            // update longest match
            if (match_len > longest_len) {
                longest_len = match_len;
                longest_match = rt_walker;
            }
        }
        // move to next routing table entry
        rt_walker = rt_walker->next;
    }

    return longest_match;
}


void send_packet_to_next_hop(struct sr_instance* sr, uint8_t* pkt, unsigned int len, sr_ip_hdr_t* ip_hdr, struct sr_if* out_iface, unsigned char* next_hop_mac) {
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) pkt;
    memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, next_hop_mac, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);

    sr_send_packet(sr, pkt, len, out_iface->name);
}



/*
types 3 and 11
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type 0
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-

*/

void send_icmp_message(struct sr_instance* sr, uint8_t *request_pkt, uint8_t type, uint8_t code, unsigned int len, struct sr_if* iface){
    if (type == 8){
        send_icmp_echo_reply(sr, request_pkt, len, iface);
    }
    else if (type == 3 || type == 11){
        send_icmp_generic(sr, request_pkt, type, code, len, iface);
    }
    else {
        fprintf(stderr, "ICMP Message type not implemented\n");
    }
}

/* refactor, a lot of duplication b/w these two */

void send_icmp_echo_reply(struct sr_instance* sr, uint8_t *request_pkt, unsigned int len, struct sr_if* iface) {
    printf("reached here");
    // get headers
    sr_ethernet_hdr_t *req_eth_hdr = (sr_ethernet_hdr_t *)request_pkt;

    // allocate space for the echo reply packet
    uint8_t *reply_pkt = (uint8_t *)malloc(len);
    memcpy(reply_pkt, request_pkt, len);  // start with a copy of the req packet

    // set up eth header
    sr_ethernet_hdr_t *rep_eth_hdr = (sr_ethernet_hdr_t *)reply_pkt;
    memcpy(rep_eth_hdr->ether_dhost, req_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(rep_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

    // set up IP header
    sr_ip_hdr_t *rep_ip_hdr = (sr_ip_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));
    uint32_t temp_ip = rep_ip_hdr->ip_src;  // swap src and dst IP addresses
    rep_ip_hdr->ip_src = rep_ip_hdr->ip_dst;
    rep_ip_hdr->ip_dst = temp_ip;
    rep_ip_hdr->ip_ttl = 64;  // reset TTL
    rep_ip_hdr->ip_sum = 0; 
    rep_ip_hdr->ip_sum = cksum(rep_ip_hdr, rep_ip_hdr->ip_hl * 4);

    // modify pkt with changed info for echo reply 
    sr_icmp_hdr_t *rep_icmp_hdr = (sr_icmp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t) + (rep_ip_hdr->ip_hl * 4));
    rep_icmp_hdr->icmp_type = 0;  // 0 is type for echo reply (echo msg is 8)
    rep_icmp_hdr->icmp_code = 0;
    rep_icmp_hdr->icmp_sum = 0; 
    rep_icmp_hdr->icmp_sum = cksum(rep_icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - (rep_ip_hdr->ip_hl * 4));

    //print_hdrs(reply_pkt, len);
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(reply_pkt);
  printf( "ICMP header:\n");
  printf("\ttype: %d\n", icmp_hdr->icmp_type);
  printf("\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  printf("\tchecksum: %d\n", icmp_hdr->icmp_sum);
    

    // send the packet
    sr_send_packet(sr, reply_pkt, len, iface->name);
    free(reply_pkt); 
}

void send_icmp_generic(struct sr_instance* sr, uint8_t *pkt, uint8_t type, uint8_t code, unsigned int len, struct sr_if* iface) {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        fprintf(stderr, "Packet too short to process for ICMP Type %d\n", type);
        return;
    }
    // det len of message 
    unsigned int icmp_payload_len = sizeof(sr_ip_hdr_t) + 8; // IP header + first 8 bytes of data
    unsigned int icmp_tot_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t) + icmp_payload_len;

    // allocate mem for pkt
    uint8_t *icmp_pkt = (uint8_t *)malloc(icmp_tot_len);
    memset(icmp_pkt, 0, icmp_tot_len);

    // eth header
    sr_ethernet_hdr_t *req_eth_hdr = (sr_ethernet_hdr_t *)pkt;
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_pkt;
    memcpy(eth_hdr->ether_dhost, req_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);

    // ip header
    sr_ip_hdr_t *req_ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(icmp_pkt + sizeof(sr_ethernet_hdr_t));
    setup_ip_header(ip_hdr, icmp_tot_len - sizeof(sr_ethernet_hdr_t), req_ip_hdr, iface);

    // ICMP header
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(ip_hdr + 1);
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 1500; 
    memcpy(icmp_hdr->data, req_ip_hdr, icmp_payload_len); // include IP header + first 8 bytes of data

    // checksum
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t) + icmp_payload_len);

    // send
    sr_send_packet(sr, icmp_pkt, icmp_tot_len, iface->name);
    free(icmp_pkt);
}

void setup_ip_header(sr_ip_hdr_t *ip_hdr, unsigned int total_len, sr_ip_hdr_t *req_ip_hdr, struct sr_if* iface) {
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(total_len);
    ip_hdr->ip_id = htons(0);
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = ip_protocol_icmp;
    ip_hdr->ip_src = iface->ip;
    ip_hdr->ip_dst = req_ip_hdr->ip_src;
    
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}


