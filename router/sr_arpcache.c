#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
/* pseudo: void sr_arpcache_sweepreqs(struct sr_instance *sr) {
       for each request on sr->cache.requests:
           handle_arpreq(request)
}*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    struct sr_arpreq *curr_req, *next_req;
    // iterate through arp request queue
    for (curr_req = sr->cache.requests; curr_req != NULL; curr_req = next_req){
        // save next ptr before handle_arpreq in case curr_req is destroyed
        next_req = curr_req->next;
        // handle arp request based on current state (re send or destory)
        handle_arpreq(sr, curr_req);
    }
}
/* 
    Send an ARP request about once a second until a reply comes back 
    or you have sent seven requests. Re-send any outstanding ARP requests that 
    haven't been sent in the past second. If an ARP request has been sent 7 times 
    with no response, a destination host unreachable should go back to all 
    the sender of packets that were waiting on a reply to this ARP request.
*/
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req){
    // check if the request is older than 1 second 
    if (difftime(time(NULL), req->sent) >= 1.0) {
        // check how many times the request has been sent
        if (req->times_sent >= 7) {
            // if has been sent 7 times w/ no response, send host unreachable
            fprintf(stderr, "ARP req timed out. Sending host unreachable");
            struct sr_packet *waiting_packet = req->packets;
            while (waiting_packet) {
                struct sr_if *outgoing_iface = sr_get_interface(sr, waiting_packet->iface);
                if (!outgoing_iface) {
                    fprintf(stderr, "Error: No outgoing interface found for ARP response.\n");
                } 
                else {
                    send_icmp_message(sr, waiting_packet->buf, 3, 1, waiting_packet->len, outgoing_iface);
                }
                waiting_packet = waiting_packet->next;
            }

            // destroy arp request
            sr_arpreq_destroy(&sr->cache, req);
        } else {
            // retry sending request if sent fewer than 7 times
            send_arp_request(sr, req);
            
            // update time sent and increment times sent
            req->sent = time(NULL);
            req->times_sent++;
        }
    }
}
// crafts and sends arp request to IP addr within request
void send_arp_request(struct sr_instance *sr, struct sr_arpreq *req) {
     // Get the interface from which to send the ARP request
    struct sr_if* interface = sr_get_interface(sr, req->packets->iface);
    if (!interface) {
        fprintf(stderr, "send_arp_request: Interface not found.\n");
        return;
    }

    /* craft packet */
    unsigned char *arp_req_packet = (unsigned char *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)arp_req_packet;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(arp_req_packet + sizeof(sr_ethernet_hdr_t));

    /* ethernet header */
    memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN); // broadcast MAC address
    memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN); // MAC address from interface
    eth_hdr->ether_type = htons(ethertype_arp); // arp type

    /* arp header */
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(arp_op_request);
    memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN); // sender hw address
    arp_hdr->ar_sip = interface->ip; // sender ip
    memset(arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = req->ip; // target ip

    sr_send_packet(sr, arp_req_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface->name);
    free(arp_req_packet);
}


void send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t *arp_hdr, struct sr_if* iface) {
    if (sr == NULL || arp_hdr == NULL || iface == NULL) {
        fprintf(stderr, "null parameters in send arp reply\n");
        return;
    }

    // allocate space for pkt
    unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
    if (reply_pkt == NULL) {
        fprintf(stderr, "failed to allocate memory for ARP reply\n");
        return;
    }

    // ethernet header
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)reply_pkt;
    memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN); // ethernet dest to the source of the ARP request
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN); // ethernet src to the MAC address of the router's interface
    eth_hdr->ether_type = htons(ethertype_arp);

    // arp header
    sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));
    reply_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    reply_arp_hdr->ar_pro = htons(ethertype_ip);
    reply_arp_hdr->ar_hln = ETHER_ADDR_LEN;
    reply_arp_hdr->ar_pln = sizeof(uint32_t);
    reply_arp_hdr->ar_op = htons(arp_op_reply); // set operation to ARP reply
    memcpy(reply_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN); // sender hardware address to MAC address of router's interface
    reply_arp_hdr->ar_sip = iface->ip; // sender protocol address to IP address of router's interface
    memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN); // target hardware address to MAC address of ARP requester
    reply_arp_hdr->ar_tip = arp_hdr->ar_sip; // target protocol address to sender IP addr from ARP request

    // send pkt
    int send_result = sr_send_packet(sr, reply_pkt, reply_len, iface->name);
    if (send_result < 0) {
        fprintf(stderr, "Error sending ARP reply\n");
    }

    // free (not lent)
    free(reply_pkt);
}


// void send_icmp_host_unreachable(struct sr_instance *sr, struct sr_arpreq *req) {
//     struct sr_packet *packet;
//     for (packet = req->packets; packet; packet = packet->next) {
//         struct sr_if *interface = sr_get_interface(sr, packet->iface);
//         if (!interface) {
//             fprintf(stderr, "send_icmp_host_unreachable: Interface not found.\n");
//             continue;
//         }

//         size_t icmp_tot_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
//         unsigned char *icmp_packet = (unsigned char *)malloc(icmp_tot_len);
//         sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
//         sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
//         sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

//         /* ethernet header */
//         memcpy(eth_hdr->ether_dhost, packet->buf + sizeof(sr_ethernet_hdr_t), ETHER_ADDR_LEN); // dest MAC (original sender)
//         memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN); // Source MAC (router interface)
//         eth_hdr->ether_type = htons(ethertype_ip); // IP type

//         /* IP header */
//         ip_hdr->ip_hl = 5; // header len
//         ip_hdr->ip_v = 4; // version
//         ip_hdr->ip_tos = 0; // type of service
//         ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)); // total len
//         ip_hdr->ip_id = 0; // id
//         ip_hdr->ip_off = htons(IP_DF); // Don't fragment
//         ip_hdr->ip_ttl = 64; // TTL
//         ip_hdr->ip_p = ip_protocol_icmp; // protocol
//         ip_hdr->ip_sum = 0; // pre-calc checksum
//         ip_hdr->ip_src = interface->ip; // src IP address
//         ip_hdr->ip_dst = ((sr_ip_hdr_t *)(packet->buf + sizeof(sr_ethernet_hdr_t)))->ip_src; // dest IP (og sender)
//         ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t)); // calc checksum

//         /* ICMP header */
//         icmp_hdr->icmp_type = 3; // dest unreachable code
//         icmp_hdr->icmp_code = 1; // host unreachable code
//         icmp_hdr->icmp_sum = 0; // pre-calc checksum 
//         icmp_hdr->unused = 0;
//         icmp_hdr->next_mtu = 0;
//         memcpy(icmp_hdr->data, packet->buf + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE); // og IP header + 8B of payload
//         icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t)); // Calculate checksum

//         sr_send_packet(sr, icmp_packet, icmp_tot_len, interface->name);

//         free(icmp_packet); // free alloc mem
//     }
// }



/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

