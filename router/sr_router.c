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

  /* fill in code here */
  /* define ARP or IP packet*/
  uint16_t eType = ethertype(packet);
  if(eType == 0x0806){
    printf("We receive an arp packet\n");
  }
  else if (eType == 0x0800){
    printf("We receive an ip packet\n"); 
  }
  /* It's ARP */
  if(eType == 0x0806){
    sr_handlearp(sr, packet, len, interface); 
  }
  else if (eType == 0x0800){
    sr_handleip(sr, packet, len, interface); 
  }

  /* It's IP */

}/* end sr_ForwardPacket */

/* This func is for handle arp packet */

void sr_handlearp (struct sr_instance* sr, 
        uint8_t * packet, 
        unsigned int len, 
        char* interface)
{
  /* get ethernet head */
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;

  /* read arp head */
  sr_arp_hdr_t *arpdr = (uint8_t *)malloc(sizeof(sr_arp_hdr_t));
  memcpy(arpdr, packet+sizeof(sr_ethernet_hdr_t), sizeof(sr_arp_hdr_t));
  
  if(ntohs(arpdr->ar_op) == 0x0001){
    /* It's arp request */
    printf("We receive an arp request\n"); 
    /* fill arp replay */
    arpdr->ar_op = htons(0x0002);
    /* Get and fill send arp header*/
    struct sr_if* arpIf = sr_get_interface(sr, interface);
    memcpy(arpdr->ar_sha, arpIf->addr, ETHER_ADDR_LEN); 
    memcpy(arpdr->ar_tha, ehdr->ether_shost, ETHER_ADDR_LEN); 
    uint32_t temp = arpdr->ar_sip;
    arpdr->ar_sip = arpdr->ar_tip;
    arpdr->ar_tip = temp;
    printf("Arp header filled\n"); 
    /* Create packet */
    int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *sendPackt = (uint8_t *)malloc(len);

    /* fill send ether header */
    sr_ethernet_hdr_t *sendEhdr = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t));
    memcpy(sendEhdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(sendEhdr->ether_shost, arpIf->addr, ETHER_ADDR_LEN);
    sendEhdr->ether_type = htons(0x0806);
    printf("Ether head filled\n"); 
    memcpy(sendPackt, sendEhdr, sizeof(sr_ethernet_hdr_t) );
    memcpy(sendPackt + sizeof(sr_ethernet_hdr_t), arpdr, sizeof(sr_arp_hdr_t));
    printf("Packet filled\ns");
    sr_send_packet(sr, sendPackt, len, interface);
    return;            
  }
  else if(arpdr->ar_op == 0x0002){
    /* It's arp request */
  }
} 

/* This func is for handle ip packet */
void sr_handleip(struct sr_instance* sr, 
      uint8_t * packet, 
      unsigned int len, 
      char* interface)
{
  /* Check sum*/
  sr_ip_hdr_t *ipdrIn = (uint8_t*) malloc(sizeof(sr_ip_hdr_t));
  memcpy(ipdrIn, packet+sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
  /* extract without sum ip header */
  uint8_t* ipdrNoSum = (uint8_t*) malloc(sizeof(sr_ip_hdr_t)-2);
  memcpy(ipdrNoSum, (uint8_t*)ipdrIn, sizeof(sr_ip_hdr_t)-10);
  memcpy(ipdrNoSum+sizeof(sr_ip_hdr_t)-10, (uint8_t*)ipdrIn+sizeof(sr_ip_hdr_t)-8, 8);
  /* compare */
  if (ipdrIn->ip_sum == cksum (ipdrNoSum, sizeof(sr_ip_hdr_t)-2)){
    /*the check sum is right*/
    /*check if it is for me*/
    uint32_t destIp = ntohl(ipdrIn->ip_dst);
    int flagForMe = 0;
    struct sr_if* tempIfList = sr->if_list;
    while(tempIfList != NULL){
      if (ntohl(tempIfList->ip) == destIp){
        flagForMe = 1;
      }
      tempIfList = tempIfList->next;
    }

    if(flagForMe == 1){
      /* this packet is for me */
      /* check its type */
      uint8_t ipProtocol = ip_protocol(packet);
      if(ipProtocol == 0x0001){
        /* it's ICMP */
        printf("hahaha\n");
      }
    }
    else{
      /* this packet is not for me */
      /* decrement TTL */
      sr_ip_hdr_t *ipdrOut = (uint8_t*) malloc(sizeof(sr_ip_hdr_t));
      memcpy(ipdrOut, packet+sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
      ipdrOut->ip_ttl = ipdrOut->ip_ttl - 1;
      /* recalculate cksum */
      uint8_t* ipdrNoSumNew = (uint8_t*) malloc(sizeof(sr_ip_hdr_t)-2);
      memcpy(ipdrNoSumNew, (uint8_t*)ipdrOut, sizeof(sr_ip_hdr_t)-10);
      memcpy(ipdrNoSumNew+sizeof(sr_ip_hdr_t)-10, (uint8_t*)ipdrOut+sizeof(sr_ip_hdr_t)-8, 8);
      ipdrOut->ip_sum = cksum (ipdrNoSumNew, sizeof(sr_ip_hdr_t)-2);
      
    }
  }
  else{
    printf("wrong checksum\n");
  }

}








