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
    /* It's ARP */
    sr_handlearp(sr, packet, len, interface); 
  }
  else if (eType == 0x0800){
    /* It's IP */
    sr_handleip(sr, packet, len, interface); 
  }

  

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
    /* fill arp replay */
    arpdr->ar_op = htons(0x0002);
    /* Get and fill send arp header*/
    struct sr_if* arpIf = sr_get_interface(sr, interface);
    memcpy(arpdr->ar_sha, arpIf->addr, ETHER_ADDR_LEN); 
    memcpy(arpdr->ar_tha, ehdr->ether_shost, ETHER_ADDR_LEN); 
    uint32_t temp = arpdr->ar_sip;
    arpdr->ar_sip = arpdr->ar_tip;
    arpdr->ar_tip = temp;
    /* Create packet */
    int templen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *sendPacket = (uint8_t *)malloc(templen);

    /* fill send ether header */
    sr_ethernet_hdr_t *sendEhdr = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t));
    memcpy(sendEhdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(sendEhdr->ether_shost, arpIf->addr, ETHER_ADDR_LEN);
    sendEhdr->ether_type = htons(0x0806);
    memcpy(sendPacket, sendEhdr, sizeof(sr_ethernet_hdr_t) );
    memcpy(sendPacket + sizeof(sr_ethernet_hdr_t), arpdr, sizeof(sr_arp_hdr_t));
    sr_send_packet(sr, sendPacket, templen, interface);
    return;            
  }
  else if(ntohs(arpdr->ar_op) == 0x0002){
    /* It's arp reply */
    struct sr_arpreq * getReq = sr_arpcache_insert(&(sr->cache), arpdr->ar_sha, arpdr->ar_sip);
    if(getReq != NULL){
      /* forwarding! */
      struct sr_packet* pPacket = getReq->packets;

      while(pPacket != NULL){
        uint8_t* outPacket = (uint8_t*) malloc(pPacket->len);
        memcpy(outPacket, pPacket->buf, pPacket->len);

        sr_ethernet_hdr_t* sendEhdr = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t));
        memcpy((uint8_t*)sendEhdr, outPacket, sizeof(sr_ethernet_hdr_t));
        memcpy(sendEhdr->ether_dhost, arpdr->ar_sha, ETHER_ADDR_LEN);
        memcpy(sendEhdr->ether_shost, arpdr->ar_tha, ETHER_ADDR_LEN);
        /* TLL decrement */
        sr_ip_hdr_t* sendIp = (uint8_t*) malloc(sizeof(sr_ip_hdr_t));
        memcpy((uint8_t*)sendIp, outPacket+sizeof(sr_ethernet_hdr_t), 
          sizeof(sr_ip_hdr_t));
        sendIp->ip_ttl = sendIp->ip_ttl - 1;
        sendIp->ip_sum = 0;
        sendIp->ip_sum = cksum(sendIp, sizeof(sr_ip_hdr_t));

        memcpy(outPacket, sendEhdr, sizeof(sr_ethernet_hdr_t));
        memcpy(outPacket+sizeof(sr_ethernet_hdr_t), sendIp, sizeof(sr_ip_hdr_t));

        /*get interface name*/
        struct sr_if* ifList = sr->if_list;
        struct sr_if* if_walker = 0;
        while(ifList != NULL){
          if(!strncmp(ifList->addr,arpdr->ar_tha,ETHER_ADDR_LEN)){ 
            if_walker = ifList;
            break;
          }
          ifList = ifList->next;
        }
        sr_send_packet(sr, outPacket, pPacket->len, if_walker->name);
        pPacket = pPacket->next;
      }
    }
    sr_arpreq_destroy(&(sr->cache), getReq);
    return;
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

    if(ipdrIn->ip_ttl == 1){
      /* if ttl is zero */
      sr_send_icmp3(sr, packet, len, 11, 0, interface);
      return;
    }
        


    /*check if it is for me*/
    uint32_t destIp = ntohl(ipdrIn->ip_dst);
    int flagForMe = 0;
    struct sr_if* tempIfList = sr->if_list;
    while(tempIfList != NULL){
      if (ntohl(tempIfList->ip) == destIp){
        flagForMe = 1;
        break;
      }
      tempIfList = tempIfList->next;
    }

    if(flagForMe == 1){
      /* this packet is for me */
      /* check its type */
      uint8_t ipProtocol = ipdrIn->ip_p;
      if(ipProtocol == 0x0001){
        /* it's ICMP */
        /* create packet */
        uint8_t *outPacket = (uint8_t*) malloc(len);

        /* create out icmp not 3 header */
        sr_icmp_hdr_t* sendIcmp = (uint8_t*) malloc(len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
        memcpy(sendIcmp, packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), 
          len-sizeof(sr_ip_hdr_t)-sizeof(sr_ethernet_hdr_t));
        sendIcmp->icmp_type = 0;
        uint8_t* icmpNoSum = (uint8_t*) malloc(len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)-2);
        memcpy(icmpNoSum, (uint8_t*)sendIcmp, 2);
        memcpy(icmpNoSum+2, (uint8_t*)sendIcmp+4, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)-4);
        sendIcmp->icmp_sum = cksum(icmpNoSum, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)-2);
        
        /* create out ip header */
        sr_ip_hdr_t *sendIp = (uint8_t*) malloc(sizeof(sr_ip_hdr_t));
        memcpy(sendIp, packet+sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
        uint32_t tempIp = sendIp->ip_dst;
        sendIp->ip_dst = sendIp->ip_src;
        sendIp->ip_src = tempIp;
        
        uint8_t* ipNoSum = (uint8_t*) malloc(sizeof(sr_ip_hdr_t)-2);
        memcpy(ipNoSum, (uint8_t*)sendIp, sizeof(sr_ip_hdr_t)-10);
        memcpy(ipNoSum+sizeof(sr_ip_hdr_t)-10, (uint8_t*)sendIp+sizeof(sr_ip_hdr_t)-8, 8);
        sendIp->ip_sum = cksum (ipNoSum, sizeof(sr_ip_hdr_t)-2);
        
        /* fill send ether header */
        sr_ethernet_hdr_t *sendEhdr = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t));
        memcpy(sendEhdr, packet, sizeof(sr_ethernet_hdr_t));
        uint8_t* tempEthAddr = (uint8_t*) malloc(ETHER_ADDR_LEN);
        memcpy(tempEthAddr, sendEhdr->ether_dhost, ETHER_ADDR_LEN);
        memcpy(sendEhdr->ether_dhost, sendEhdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(sendEhdr->ether_shost, tempEthAddr, ETHER_ADDR_LEN);
        
        /* fill packet */
        memcpy(outPacket, sendEhdr, sizeof(sr_ethernet_hdr_t));
        memcpy(outPacket+sizeof(sr_ethernet_hdr_t), sendIp, sizeof(sr_ip_hdr_t));
        memcpy(outPacket+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), 
          sendIcmp, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
        
        sr_send_packet(sr, outPacket, len, interface);
        return;
      }
      else{
        /* it may udp or tcp */
        /* send icmp3 back */
        sr_send_icmp3(sr, packet, len, 3, 3, interface);
        return;
      }
    }
    else{
      /* this packet is not for me */
      /* LPM */
      struct sr_rt* selectedSr = LPM(destIp, sr);
      if(selectedSr != NULL){
        /* rtable ip matched */
        /* check if in cache */     
        struct sr_arpentry * findEntry = sr_arpcache_lookup(&(sr->cache), htonl(destIp));
        if(findEntry == NULL){
          /* not in cache, add arp request in queue*/
          sr_arpcache_queuereq(&(sr->cache), htonl(destIp), packet, len, interface);                                     
        }
        else{
          /* forwarding */


          /* get out-interface */
          struct sr_if* outIf = sr_get_interface(sr, selectedSr->interface);
          /* get dest-mac */
          uint8_t *macAddr = (uint8_t *) malloc(6);
          memcpy(macAddr, findEntry->mac, 6);
          
          uint8_t* outPacket = (uint8_t*) malloc(len);
          memcpy(outPacket, packet, len);

          sr_ethernet_hdr_t* sendEhdr = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t));
          memcpy((uint8_t*)sendEhdr, outPacket, sizeof(sr_ethernet_hdr_t));
          memcpy(sendEhdr->ether_dhost, macAddr, ETHER_ADDR_LEN);
          memcpy(sendEhdr->ether_shost, outIf->addr, ETHER_ADDR_LEN);
          /* TLL decrement */
          sr_ip_hdr_t* sendIp = (uint8_t*) malloc(sizeof(sr_ip_hdr_t));
          memcpy((uint8_t*)sendIp, outPacket+sizeof(sr_ethernet_hdr_t), 
            sizeof(sr_ip_hdr_t));
          /* check ttl */ 
          sendIp->ip_ttl = sendIp->ip_ttl - 1;


          sendIp->ip_sum = 0;
          sendIp->ip_sum = cksum(sendIp, sizeof(sr_ip_hdr_t));

          memcpy(outPacket, sendEhdr, sizeof(sr_ethernet_hdr_t));
          memcpy(outPacket+sizeof(sr_ethernet_hdr_t), sendIp, sizeof(sr_ip_hdr_t));

          sr_send_packet(sr, outPacket, len, outIf->name);

          free(findEntry);
        }
      }
      else{
        /* rtable ip isn't matched */
        /* send ICMP network unreachable back */
        sr_send_icmp3(sr, packet, len, 3, 0, interface);
        
      }
    }
  }     
  else{
    printf("wrong checksum\n");
    return;
  }
}

/* this func is for calculate LPM */
struct sr_rt* LPM(uint32_t ip, struct sr_instance *sr){
  struct sr_rt *temproutingtable = sr->routing_table;
  int counter = 0;
  struct sr_rt *result;
  uint8_t map[8] = {128,192,224,240,248,252,254,255};
  while(temproutingtable != NULL){
    uint8_t m1 = (ntohl(temproutingtable->mask.s_addr) & 0xff000000)>>24;
    uint8_t m2 = (ntohl(temproutingtable->mask.s_addr) & 0x00ff0000)>>16;
    uint8_t m3 = (ntohl(temproutingtable->mask.s_addr) & 0x0000ff00)>>8;
    uint8_t m4 = (ntohl(temproutingtable->mask.s_addr) & 0x000000ff);
    int c_mask = 0;
    int i;
    for(i = 0; i < 8; i++){
      if(m1 == map[i]){
        c_mask = i + 1;
      }
    }
    for(i = 0; i < 8; i++){
      if(m2 == map[i]){
        c_mask = c_mask + i + 1;
      }
    }
    for(i = 0; i < 8; i++){
      if(m3 == map[i]){
        c_mask = c_mask + i + 1;
      }
    }
    for(i = 0; i < 8; i++){
      if(m4 == map[i]){
        c_mask = c_mask + i + 1;
      }
    }
    uint32_t tempdest = ntohl(temproutingtable->dest.s_addr) & ntohl(temproutingtable->mask.s_addr);
    if (tempdest == (ip & ntohl(temproutingtable->mask.s_addr))){
      if (counter < c_mask){
        counter = c_mask;
        result = temproutingtable;
      }
    }
    temproutingtable = temproutingtable->next;
  }
  return result;
}

/* this func is for send icmp3 not icmp  */
void sr_send_icmp3(struct sr_instance *sr, uint8_t * packet, unsigned int len, uint8_t icmp_type,
  uint8_t icmp_code, char* interface){
  int len1 = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *outPacket = (uint8_t *) malloc(len1);
  sr_icmp_t3_hdr_t * sendIcmp = (uint8_t*) malloc(sizeof(sr_icmp_t3_hdr_t));
  sendIcmp->icmp_type = icmp_type;
  sendIcmp->icmp_code = icmp_code;
  memcpy(sendIcmp->data, packet+sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
  sendIcmp->icmp_sum = 0;
  sendIcmp->icmp_sum = cksum(sendIcmp, sizeof(sr_icmp_t3_hdr_t));

  sr_ip_hdr_t *sendIp = (uint8_t*) malloc(sizeof(sr_ip_hdr_t));
  memcpy(sendIp, packet+sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
  sendIp->ip_len = htons(sizeof(sr_ip_hdr_t)+ sizeof(sr_icmp_t3_hdr_t));
  sendIp->ip_p = ip_protocol_icmp;

  /*  loop for its if */
  struct sr_if* ifList = sr->if_list;
  uint32_t tempIp = 0;
  while(ifList != NULL){
    if(sendIp->ip_dst == ifList->ip){
      tempIp = ifList->ip;
      break;
    }
    ifList = ifList->next;
  }
  if(tempIp == 0){
    struct sr_if* myIf = sr_get_interface(sr, interface);
    tempIp = myIf->ip;
  }
  sendIp->ip_dst = sendIp->ip_src;
  sendIp->ip_src = tempIp;
  sendIp->ip_ttl = INIT_TTL;
  sendIp->ip_sum = 0;
  sendIp->ip_sum = cksum(sendIp, sizeof(sr_ip_hdr_t));

  sr_ethernet_hdr_t *sendEhdr = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t));
  memcpy(sendEhdr, packet, sizeof(sr_ethernet_hdr_t));
  uint8_t* tempEthAddr = (uint8_t*) malloc(ETHER_ADDR_LEN);
  memcpy(tempEthAddr, sendEhdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(sendEhdr->ether_dhost, sendEhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(sendEhdr->ether_shost, tempEthAddr, ETHER_ADDR_LEN);

  memcpy(outPacket, sendEhdr, sizeof(sr_ethernet_hdr_t));
  memcpy(outPacket+sizeof(sr_ethernet_hdr_t), sendIp, sizeof(sr_ip_hdr_t));
  memcpy(outPacket+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), sendIcmp, 
    sizeof(sr_icmp_t3_hdr_t));

  sr_send_packet(sr,outPacket,len1,interface);
}