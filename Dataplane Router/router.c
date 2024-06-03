#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "list.h"

#define TIME_EXCEEDED 0x0b
#define DEST_UNREACHABLE 0x03
#define ARP_TYPE 0x0806
#define IP_TYPE 0x0800

/* Structura pentru tabela de rutare */
struct route_table_entry *route_table;
int route_table_len;

/* Structura pentru tabela ARP*/
struct arp_table_entry *arp_table;
int arp_table_len;

/* Functie pentru interschimbare a doua valori de tip uint32_t */
void mySwap(uint32_t *x, uint32_t *y) {
	uint32_t z = *x;
	*x = *y;
	*y = z;
}

/*
* Functia care cauta in tabela ARP pentru a obtine adresa MAC
* corespunzatoare unei adrese IP 
*/
struct arp_table_entry *get_arp_entry(uint32_t sought_ip) {
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == sought_ip) {
            return &arp_table[i];
        }
    }

    return NULL;
}

/* 
* Functie care cauta in tabela de rutare pentru a obtine 
* cea mai buna ruta pentru o destinatie
*/
struct route_table_entry *get_best_route(uint32_t dest_ip) {
    struct route_table_entry *best_route = NULL;
    uint32_t best_mask = 0;

    for (int i = 0; i < route_table_len; i++) {
        if ((dest_ip & route_table[i].mask) == route_table[i].prefix) {
            uint32_t mask = ntohl(route_table[i].mask);
            // Se alege ruta cu masca cea mai lunga
            if (mask > best_mask) {
                best_mask = mask;
                best_route = &route_table[i];
            }
        }
    }

    return best_route;
}

/* Functie care trimite trimite un mesaj ICMP Time Exceeded */
void send_icmp_ttl_exceeded(int interface, struct ether_header *eth_hdr, struct iphdr *ip_hdr, char *buffer) {
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    
	// Se seteaza campurile pentru ICMP
    icmp_hdr->type = TIME_EXCEEDED;
	icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	memcpy(buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr) + 8);

	mySwap(&ip_hdr->saddr, &ip_hdr->daddr); // Se inverseaza adresele IP pentru raspuns
	ip_hdr->ttl = 64;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));

    // Trimiterea pachetului
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    get_interface_mac(interface, eth_hdr->ether_shost);
    send_to_link(interface, buffer, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
}

/* Functie care trimite un mesaj de tip ICMP Destination Unreachable */
void send_icmp_dest_unreachable(int interface, struct ether_header *eth_hdr, struct iphdr *ip_hdr, char *buffer) {
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    
	// Se seteaza campurile pentru ICMP
    icmp_hdr->type = DEST_UNREACHABLE;
	icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	memcpy(buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr) + 8);

	mySwap(&ip_hdr->saddr, &ip_hdr->daddr); // Se inverseaza adresele IP pentru raspuns
	ip_hdr->ttl = 64;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));

    // Trimiterea pachetului
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    get_interface_mac(interface, eth_hdr->ether_shost);
    send_to_link(interface, buffer, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	//size_t len;

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Se aloca tabela de rutare și ARP */
    route_table = malloc(sizeof(struct route_table_entry) * 100000);
    DIE(route_table == NULL, "memory route");
    route_table_len = read_rtable(argv[1], route_table);

    arp_table = malloc(sizeof(struct arp_table_entry) * 100);
    DIE(arp_table == NULL, "memory arp");
    arp_table_len = parse_arp_table("arp_table.txt", arp_table);


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		if (ntohs(eth_hdr->ether_type) == IP_TYPE) {
    		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			// Salvam checksum-ul original si il calculam pe cel nou
    		uint16_t original_checksum = ntohs(ip_hdr->check);
    		ip_hdr->check = 0; 
    		uint16_t calculated_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)); 

    		if (original_checksum != calculated_checksum) {
				// Se ignora pachetul daca checksum-ul e invalid
        		continue;
    		}

			ip_hdr->ttl--;
			if (ip_hdr->ttl <= 1) {
				send_icmp_ttl_exceeded(interface, eth_hdr, ip_hdr, buf);
				continue;
			}

			// Recalcularea checksum-ului dupa ce decrementam ttl
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

            struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
            if (best_route == NULL) {
				// Daca nu exista ruta, se trimite mesajul Destination Unreachable
				send_icmp_dest_unreachable(interface, eth_hdr, ip_hdr, buf);
                continue;
            }

			// Cautam adresa mac a urmatorului hop in tabela ARP
            struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
            if (arp_entry == NULL) {
				// Daca nu se gaseste, se ignora pachetul
                continue; 
            }

			// Se seteaza adresa MAC destinatie si adresa Mac sursa
            memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);
            get_interface_mac(best_route->interface, eth_hdr->ether_shost);

            send_to_link(best_route->interface, buf, len);
        }
	} 
}