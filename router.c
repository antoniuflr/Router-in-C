#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include "string.h"
#include <arpa/inet.h>


#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define MAX_RTABLE_ENTRIES 100000
#define MAX_ARP_ENTRIES 10

int main(int argc, char *argv[])
{

	setvbuf(stdout, NULL, _IONBF, 0);


	char buf[MAX_PACKET_LEN];

	fprintf(stdout, "Router started\n");

	// Do not modify this line
	init(argv + 2, argc - 2);

	struct route_table_entry *rtable = (struct route_table_entry *)malloc(sizeof(struct route_table_entry) * MAX_RTABLE_ENTRIES);
	int rtable_size = read_rtable(argv[1], rtable);
	
	// Sort the routing table by prefix length and value for bsearch
	qsort((void *)rtable, (size_t)rtable_size, sizeof(struct route_table_entry), cmp_prefix);

	// Allocate arp table
	struct arp_table_entry *arp_table = (struct arp_table_entry *)calloc(MAX_ARP_ENTRIES, sizeof(struct arp_table_entry));
	int arp_table_size = 0;

	queue q = create_queue();

	while (1)
	{

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// TODO: Implement the router forwarding logic

		/* Note that packets received are in network order,
			any header field which has more than 1 byte will need to be conerted to
			host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
			sending a packet on the link, */

		fprintf(stdout, "\n");

		// Parse the packet or dump
		struct ether_hdr *recv_ethr_hdr = (struct ether_hdr *)buf;

		fprintf(stdout, "Received packet of length %ld on interface %ld\n", len, interface);

		// Interface MAC address
		uint8_t *interface_mac = (uint8_t *)calloc(6, sizeof(uint8_t));
		get_interface_mac(interface, interface_mac);

		fprintf(stdout, "Interface MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			interface_mac[0], interface_mac[1], interface_mac[2],
			interface_mac[3], interface_mac[4], interface_mac[5]);

		// Check if the packet is for us or everyone or dump
		if (memcmp(recv_ethr_hdr->ethr_dhost, interface_mac, 6) != 0 &&
			memcmp(recv_ethr_hdr->ethr_dhost, "\xff\xff\xff\xff\xff\xff", 6) != 0) {
			// Dump packet
			continue;
		}

		// Interface IP address

		// Get IP in char
		char *interface_ip_char = get_interface_ip(interface);
		DIE(interface_ip_char == NULL, "get_interface_ip");
		fprintf(stdout, "Interface IP char: %s\n", interface_ip_char);

		// Convert to binary with inet_pton
		struct in_addr interface_ip_addr;

		int rc = inet_pton(AF_INET, interface_ip_char, &interface_ip_addr);
		DIE(rc != 1, "inet_pton");

		uint32_t interface_ip = interface_ip_addr.s_addr;
		
		// Check if Ether type is IPv4 or ARP
		if (recv_ethr_hdr->ethr_type == htons(ETHERTYPE_IP)) {
			fprintf(stdout, "IPv4 packet\n");
			// IPv4
			// Check if the packet is for us or dump
			struct ip_hdr *recv_ip_hdr = (struct ip_hdr *)((char *)buf + sizeof(struct ether_hdr));

			fprintf(stdout, "Interface IP: %u.%u.%u.%u\n",
				(interface_ip >> 24) & 0xFF,
				(interface_ip >> 16) & 0xFF,
				(interface_ip >> 8) & 0xFF,
				interface_ip & 0xFF);

			fprintf(stdout, "Destination IP is: %u.%u.%u.%u\n",
				(recv_ip_hdr->dest_addr >> 24) & 0xFF,
				(recv_ip_hdr->dest_addr >> 16) & 0xFF,
				(recv_ip_hdr->dest_addr >> 8) & 0xFF,
				recv_ip_hdr->dest_addr & 0xFF);

			fprintf(stdout, "Interface IP is: %u.%u.%u.%u\n",
				(interface_ip >> 24) & 0xFF,
				(interface_ip >> 16) & 0xFF,
				(interface_ip >> 8) & 0xFF,
				interface_ip & 0xFF);

			// Check if the packet is for us or redirect
			if (recv_ip_hdr->dest_addr == interface_ip) {
				fprintf(stdout, "Packet for us\n");

				// Check if its ICMP
				if (recv_ip_hdr->proto != 1)
					// Dump packet, we only respond to ICMP
					continue;

				fprintf(stdout, "ICMP packet recieved\n");

				struct icmp_hdr *recv_icmp_hdr = (struct icmp_hdr *)((char *)buf 
												+ sizeof(struct ether_hdr) 
												+ sizeof(struct ip_hdr));

				// Checksum
				uint16_t old_sum = ntohs(recv_icmp_hdr->check);

				recv_icmp_hdr->check = 0;
				uint16_t new_sum = checksum((uint16_t *)((char *)buf 
											+ sizeof(struct ether_hdr) 
											+ sizeof(struct ip_hdr)), 
											len - sizeof(struct ether_hdr) 
												- sizeof(struct ip_hdr));

				if (old_sum != new_sum)
					// Drop packet
					continue;

				fprintf(stdout, "Checksum OK\n");

				// Check if it's echo request
				if (recv_icmp_hdr->mtype != 8 || recv_icmp_hdr->mcode != 0) {
					// Dump packet, we only reply to echo requests
					fprintf(stdout, "Not an echo request\n");
					fprintf(stdout, "ICMP type: %u\n", recv_icmp_hdr->mtype);
					fprintf(stdout, "ICMP code: %u\n", recv_icmp_hdr->mcode);
					continue;
				}

				fprintf(stdout, "Echo request received\n");

				// Echo reply
				char *reply = (char *)calloc(1, len);

				// Copy ICMP packet over
				size_t icmp_hdr_off = sizeof(struct ether_hdr) + sizeof(struct ip_hdr);
				memcpy((void *)(reply + icmp_hdr_off), (void *)(buf + icmp_hdr_off), 
					   len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr));

				struct icmp_hdr *new_icmp = (struct icmp_hdr *)(reply + icmp_hdr_off);

				// Set reply code and type
				new_icmp->mcode = 0;
				new_icmp->mtype = 0;


				// Calculate new checksum
				new_icmp->check = 0;
				new_icmp->check = htons(checksum((uint16_t *)(reply + icmp_hdr_off), 
											  len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));

				// Copy IP settings over
				memcpy((void *)(reply + sizeof(struct ether_hdr)),
					   (void *)(buf + sizeof(struct ether_hdr)),
					   sizeof(struct ip_hdr));

				// Swap IP addresses in header
				struct ip_hdr *recv_ip_hdr = (struct ip_hdr *)(reply + sizeof(struct ether_hdr));

				uint32_t temp = recv_ip_hdr->dest_addr;
				recv_ip_hdr->dest_addr = recv_ip_hdr->source_addr;
				recv_ip_hdr->source_addr = temp;

				// Recalculate checksum
				recv_ip_hdr->checksum = 0;
				recv_ip_hdr->checksum = htons(checksum((uint16_t *)(reply + sizeof(struct ether_hdr)),
												 len - sizeof(struct ether_hdr)));

				// Copy ethernet settings over
				memcpy((void *)reply, (void *)buf, sizeof(struct ether_hdr));

				// Swap MAC addresses
				struct ether_hdr *reply_hdr = (struct ether_hdr *)reply;

				uint8_t temp2[6];
				memcpy(temp2, reply_hdr->ethr_dhost, 6 * sizeof(uint8_t));
				memcpy(reply_hdr->ethr_dhost, reply_hdr->ethr_shost, 6 * sizeof(uint8_t));
				memcpy(reply_hdr->ethr_shost, temp2, 6 * sizeof(uint8_t));

				// Reply complete, send it
				send_to_link(len, reply, interface);
				fprintf(stdout, "Reply sent\n");

				continue;
			}

			fprintf(stdout, "Packet not for us, redirecting\n");

			// Redirect logic

			// Remember old checksum
			uint16_t old_sum = ntohs(recv_ip_hdr->checksum);
			fprintf(stdout, "Old checksum: %u\n", old_sum);

			// Set to 0 for calculation
			recv_ip_hdr->checksum = 0;

			// Calculate checksum
			uint16_t new_sum = checksum((uint16_t *)((char *)buf + sizeof(struct ether_hdr)), len - sizeof(struct ether_hdr));
			fprintf(stdout, "New checksum: %u\n", new_sum);

			// Check if packet is corrupt
			if (old_sum != new_sum) {
				// Dump packet
				continue;
			}

			fprintf(stdout, "Checksum OK\n");
			
			// Check if TTL is 0 or 1
			if (recv_ip_hdr->ttl == 0 || recv_ip_hdr->ttl == 1) {
				// Send ICMP TTL expired
				fprintf(stdout, "TTL expired\n");

				size_t reply_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr)
									+ sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;

				char *reply = (char *)calloc(1, reply_len);

				// Copy ICMP packet over
				size_t icmp_hdr_off = sizeof(struct ether_hdr) + sizeof(struct ip_hdr);
				memcpy((void *)(reply + icmp_hdr_off), (void *)(buf + icmp_hdr_off), 
					   sizeof(struct icmp_hdr));

				struct icmp_hdr *new_icmp = (struct icmp_hdr *)(reply + icmp_hdr_off);

				// Set reply code and type
				new_icmp->mtype = 11;
				new_icmp->mcode = 0;

				//Copy original IP header in ICMP payload
				memcpy ((void *)(reply + icmp_hdr_off + sizeof(struct icmp_hdr)), 
					   (void *)(buf + sizeof(struct ether_hdr)), sizeof(struct ip_hdr));

				// Copy first 8 bytes of original IP payload into new payload
				memcpy((void *)(reply + icmp_hdr_off + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr)), 
					   (void *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)), 8);

				// Calculate new checksum
				new_icmp->check = 0;
				new_icmp->check = htons(checksum((uint16_t *)(reply + icmp_hdr_off), 
											  reply_len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));

				// Copy IP settings over
				memcpy((void *)(reply + sizeof(struct ether_hdr)),
					   (void *)(buf + sizeof(struct ether_hdr)),
					   sizeof(struct ip_hdr));

				// Swap IP addresses in header
				struct ip_hdr *recv_ip_hdr = (struct ip_hdr *)(reply + sizeof(struct ether_hdr));

				uint32_t temp = recv_ip_hdr->dest_addr;
				recv_ip_hdr->dest_addr = recv_ip_hdr->source_addr;
				recv_ip_hdr->source_addr = temp;

				// Set IP length
				recv_ip_hdr->tot_len = htons(reply_len - sizeof(struct ether_hdr));

				// Change proto to ICMP
				recv_ip_hdr->proto = 1;

				// Change TTL
				recv_ip_hdr->ttl = 100;

				// Recalculate checksum
				recv_ip_hdr->checksum = 0;
				recv_ip_hdr->checksum = htons(checksum((uint16_t *)(reply + sizeof(struct ether_hdr)),
												 reply_len - sizeof(struct ether_hdr)));

				// Copy ethernet settings over
				memcpy((void *)reply, (void *)buf, sizeof(struct ether_hdr));

				// Swap MAC addresses
				struct ether_hdr *reply_hdr = (struct ether_hdr *)reply;

				uint8_t temp2[6];
				memcpy(temp2, reply_hdr->ethr_dhost, 6 * sizeof(uint8_t));
				memcpy(reply_hdr->ethr_dhost, reply_hdr->ethr_shost, 6 * sizeof(uint8_t));
				memcpy(reply_hdr->ethr_shost, temp2, 6 * sizeof(uint8_t));

				// Reply complete, send it
				send_to_link(reply_len, reply, interface);
				fprintf(stdout, "Time exceeded sent sent\n");

				// Dump packet
				continue;
			}

			fprintf(stdout, "TTL OK\n");
			
			// Update TTL
			recv_ip_hdr->ttl--;

			struct route_table_entry *hop_entry = NULL;
			hop_entry = search_routes(rtable, 0, rtable_size - 1, recv_ip_hdr->dest_addr);
			
			if (hop_entry == NULL) {
				fprintf(stdout, "No route found to host\n");
				// ICMP reply "destination unreachable"
				size_t reply_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr)
									+ sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;

				char *reply = (char *)calloc(1, reply_len);

				// Copy ICMP packet over
				size_t icmp_hdr_off = sizeof(struct ether_hdr) + sizeof(struct ip_hdr);
				memcpy((void *)(reply + icmp_hdr_off), (void *)(buf + icmp_hdr_off), 
					   sizeof(struct icmp_hdr));

				struct icmp_hdr *new_icmp = (struct icmp_hdr *)(reply + icmp_hdr_off);

				// Set reply code and type
				new_icmp->mtype = 3;
				new_icmp->mcode = 0;

				//Copy original IP header in ICMP payload
				memcpy ((void *)(reply + icmp_hdr_off + sizeof(struct icmp_hdr)), 
					   (void *)(buf + sizeof(struct ether_hdr)), sizeof(struct ip_hdr));

				// Copy first 8 bytes of original IP payload into new payload
				memcpy((void *)(reply + icmp_hdr_off + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr)), 
					   (void *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)), 8);

				// Calculate new checksum
				new_icmp->check = 0;
				new_icmp->check = htons(checksum((uint16_t *)(reply + icmp_hdr_off), 
											  reply_len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));

				// Copy IP settings over
				memcpy((void *)(reply + sizeof(struct ether_hdr)),
					   (void *)(buf + sizeof(struct ether_hdr)),
					   sizeof(struct ip_hdr));

				// Swap IP addresses in header
				struct ip_hdr *recv_ip_hdr = (struct ip_hdr *)(reply + sizeof(struct ether_hdr));

				uint32_t temp = recv_ip_hdr->dest_addr;
				recv_ip_hdr->dest_addr = recv_ip_hdr->source_addr;
				recv_ip_hdr->source_addr = temp;

				// Set IP length
				recv_ip_hdr->tot_len = htons(reply_len - sizeof(struct ether_hdr));

				// Change proto to ICMP
				recv_ip_hdr->proto = 1;

				// Change TTL
				recv_ip_hdr->ttl = 100;

				// Recalculate checksum
				recv_ip_hdr->checksum = 0;
				recv_ip_hdr->checksum = htons(checksum((uint16_t *)(reply + sizeof(struct ether_hdr)),
												 reply_len - sizeof(struct ether_hdr)));

				// Copy ethernet settings over
				memcpy((void *)reply, (void *)buf, sizeof(struct ether_hdr));

				// Swap MAC addresses
				struct ether_hdr *reply_hdr = (struct ether_hdr *)reply;

				uint8_t temp2[6];
				memcpy(temp2, reply_hdr->ethr_dhost, 6 * sizeof(uint8_t));
				memcpy(reply_hdr->ethr_dhost, reply_hdr->ethr_shost, 6 * sizeof(uint8_t));
				memcpy(reply_hdr->ethr_shost, temp2, 6 * sizeof(uint8_t));

				// Reply complete, send it
				send_to_link(reply_len, reply, interface);
				fprintf(stdout, "Destination not reached sent sent\n");

				// Dump packet
				continue;
			}

			uint32_t next_hop_ip = hop_entry->next_hop;
			int interface_out = hop_entry->interface;

			fprintf(stdout, "Next hop IP: %u.%u.%u.%u\n",
				(next_hop_ip >> 24) & 0xFF,
				(next_hop_ip >> 16) & 0xFF,
				(next_hop_ip >> 8) & 0xFF,
				next_hop_ip & 0xFF);

			fprintf(stdout, "Next hop interface: %d\n", interface_out);

			// Calculate new checksum
			recv_ip_hdr->checksum = 0;
			recv_ip_hdr->checksum = htons(checksum((uint16_t *)((char *)buf + sizeof(struct ether_hdr)), len - sizeof(struct ether_hdr)));
			fprintf(stdout, "New checksum: %u\n", ntohs(recv_ip_hdr->checksum));

			// Rewrite L2 header with next hop

			// We need MAC address of next hop so we use ARP

			// Search cache first
			int found = 0;
			uint8_t *next_hop_mac = (uint8_t *)calloc(6, sizeof(uint8_t));
			for (int i = 0; i < arp_table_size; i++) {
				if (arp_table[i].ip == next_hop_ip) {
					// Found MAC address
					for (int j = 0; j < 6; j++)
						next_hop_mac[j] = arp_table[i].mac[j];
					found = 1;
					break;
				}
			}

			if (found) {
				fprintf(stdout, "MAC address found in cache\n");

				// Rewrite L2 header with next hop MAC address
				memcpy(recv_ethr_hdr->ethr_dhost, next_hop_mac, 6);
				memcpy(recv_ethr_hdr->ethr_shost, interface_mac, 6);

				// Send packet on the interface to next hop
				send_to_link(len, buf, interface_out);

				fprintf(stdout, "Packet sent to next hop which is on interface %d\n", interface_out);
				continue;
			} else {
				// Generate interogation and send it
				fprintf(stdout, "MAC address not found in cache, interogating\n");

				// Get IP address of interface_out
				char *interface_out_ip_char = get_interface_ip(interface_out);

				// Convert to binary with inet_pton
				struct in_addr interface_out_ip_addr;

				int rc = inet_pton(AF_INET, interface_out_ip_char, &interface_out_ip_addr);
				DIE(rc != 1, "inet_pton");

				uint32_t interface_out_ip = interface_out_ip_addr.s_addr;

				// Get interface_out MAC
				uint8_t *interface_out_mac = (uint8_t *)calloc(6, sizeof(uint8_t));
				get_interface_mac(interface_out, interface_out_mac);
				
				// Allocate ARP request
				size_t arp_req_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
				char *arp_req = (char *)calloc(1, arp_req_len);
				
				// Populate ether header
				struct ether_hdr *arp_eth_hdr = (struct ether_hdr *)arp_req;
				memcpy((void *)arp_eth_hdr->ethr_dhost, "\xff\xff\xff\xff\xff\xff", 6);
				memcpy((void *)arp_eth_hdr->ethr_shost, interface_out_mac, 6);
				arp_eth_hdr->ethr_type = htons(ETHERTYPE_ARP);
				
				// Populate ARP header
				struct arp_hdr *arp_hdr = (struct arp_hdr *)(arp_req + sizeof(struct ether_hdr));
				arp_hdr->hw_type = htons(1); // Ethernet
				arp_hdr->proto_type = htons(ETHERTYPE_IP); // IPv4
				arp_hdr->hw_len = 6; // MAC address length
				arp_hdr->proto_len = 4; // IPv4 address length
				arp_hdr->opcode = htons(1); // Request
				memcpy(arp_hdr->shwa, interface_out_mac, 6); // Sender MAC address
				arp_hdr->sprotoa = interface_out_ip; // Sender IP address
				memcpy(arp_hdr->thwa, "\xff\xff\xff\xff\xff\xff", 6); // Target MAC address
				arp_hdr->tprotoa = next_hop_ip; // Target IP address
				
				// Queue the packet
				char *buf_copy = (char *)calloc(1, len);
				memcpy(buf_copy, buf, len);
				queue_enq(q, (void *)buf_copy);
				fprintf(stdout, "Packet queued\n");

				// Send ARP request
				send_to_link(arp_req_len, arp_req, interface_out);
				fprintf(stdout, "ARP interogation sent\n");
				continue;
			}
			
		} else if (recv_ethr_hdr->ethr_type == htons(ETHERTYPE_ARP)) {
			// ARP
			fprintf(stdout, "ARP packet\n");

			// Check if it's a request or reply
			struct arp_hdr *recv_arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

			// Check if it's for us
			if (recv_arp_hdr->tprotoa != interface_ip) {
				fprintf(stdout, "ARP packet not for us\n");
				// Dump packet
				continue;
			}

			if (recv_arp_hdr->opcode == htons(1)) {
				fprintf(stdout, "ARP request\n");
				// Allocate reply
				size_t arp_reply_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
				char *arp_reply = (char *)calloc(1, arp_reply_len);

				// Populate ether header
				struct ether_hdr *arp_eth_hdr = (struct ether_hdr *)arp_reply;
				memcpy((void *)arp_eth_hdr->ethr_dhost, (void *)recv_ethr_hdr->ethr_shost, 6);
				memcpy((void *)arp_eth_hdr->ethr_shost, interface_mac, 6);
				arp_eth_hdr->ethr_type = htons(ETHERTYPE_ARP);

				// Populate ARP header
				struct arp_hdr *reply_arp_hdr = (struct arp_hdr *)(arp_reply + sizeof(struct ether_hdr));
				reply_arp_hdr->hw_type = htons(1); // Ethernet
				reply_arp_hdr->proto_type = htons(ETHERTYPE_IP); // IPv4
				reply_arp_hdr->hw_len = 6; // MAC address length
				reply_arp_hdr->proto_len = 4; // IPv4 address length
				reply_arp_hdr->opcode = htons(2); // Reply
				memcpy(reply_arp_hdr->shwa, interface_mac, 6); // Sender MAC address
				reply_arp_hdr->sprotoa = interface_ip; // Sender IP address
				memcpy(reply_arp_hdr->thwa, recv_ethr_hdr->ethr_shost, 6); // Target MAC address
				reply_arp_hdr->tprotoa = ((struct arp_hdr *)(buf + sizeof(struct ether_hdr)))->sprotoa;// Target IP address

				// Send ARP reply
				send_to_link(arp_reply_len, arp_reply, interface);	
				fprintf(stdout, "ARP reply sent\n");
				continue;

			} else if (recv_arp_hdr->opcode == htons(2)) {
				fprintf(stdout, "ARP reply\n");

				// Add in cache
				struct arp_table_entry *new_entry = &arp_table[arp_table_size];
				new_entry->ip = recv_arp_hdr->sprotoa;
				memcpy(new_entry->mac, recv_arp_hdr->shwa, 6);
				arp_table_size++;
				fprintf(stdout, "ARP entry added to cache\n");

				// Check if we have a packet waiting for this MAC address
				if (queue_empty(q)) {
					fprintf(stdout, "No packet waiting for this MAC address\n");
					continue;
				}
				struct ether_hdr *packet = (struct ether_hdr *)queue_deq(q);
				size_t packet_len = sizeof(struct ether_hdr) +
									ntohs(((struct ip_hdr *)((char *)packet + sizeof(struct ether_hdr)))->tot_len);
				if (packet != NULL) {
					// Rewrite L2 header with next hop MAC address
					memcpy(packet->ethr_dhost, new_entry->mac, 6);
					memcpy(packet->ethr_shost, interface_mac, 6);

					// Send packet on the interface to next hop
					send_to_link(packet_len, (char *)packet, interface);

					fprintf(stdout, "Packet sent to next hop which is on interface %ld\n", interface);

					continue;
				} else {
					fprintf(stdout, "No packet waiting for this MAC address\n");
					continue;
				}

			}
		} else {
			// Dump packet
			DIE(1, "Unhandled Ether type");
			continue;
		}
		
	}
}


