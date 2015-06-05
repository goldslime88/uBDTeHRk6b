Readme File of Project #2

Lijun Chen
A53071897

Firstly, I briefly describle my design decision in this project.

1. void handle_arpreq(struct sr_arpreq *req, struct sr_instance *sr)
This function is for handle arp request cached in the router.
Pseudocode:
if difftime(now, req->sent) > 1.0
           if req->times_sent >= 5:
               Send Host unreachable icmp
               arpreq_destroy(req)
           else:
               send arp request
               req->sent = now
               req->times_sent++

2. struct sr_rt* LPM(uint32_t ip, struct sr_instance *sr)
This function is for finding the longest match ip.

3. void sr_send_icmp3(struct sr_instance *sr, uint8_t * packet, unsigned int len, uint8_t icmp_type, uint8_t icmp_code, char* interface)
This function is for sending different kind of icmp3.

4. void sr_handlearp (struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
This function is for handle when the router receive an arp packet.
Pseudocode:
if arp request:
	send arp reply
else if arp reply:
	insert into arp cache
	send out all waited packets in this request

5. void sr_handleip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
This function is for handle when the router receive an ip packet.

Pseudocode:
Checksum and TTl
if checksum right:
	if TTL = 1:
		Send Time exceeded icmp
		return
	if this packet is for me:
		if it's icmp echo request
			Send icmp echo replay
		else:
			Send Port unreachable icmp
	else if this packet is not for me:
		Check LPM
		if ip matched:
			if can find MAC of this IP:
				forward this packet
			else:
				add arp request in queue

		else:
			Send Destination net unreachable icmp
else
	wrong packet

I should write more functions which will make the program more clear. 

/*  I am not competing for the George Varghese Espresso prize. */










