/*
 * Copyright (c) 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_table_lpm.h>
#include <rte_table_hash.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_port_ring.h>
#include <rte_table_stub.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_port_ethdev.h>
#include <rte_kni.h>

#ifdef STATIC_ARP
#include <rte_cfgfile.h>
#endif	/* STATIC_ARP */

#include "mngtplane_handler.h"
#include "util.h"
#include "main.h"
#include "dp_stats.h"
#include "gtpu.h"

/* ****************************************************************************
 * ****    Mngt Handler Defines/Data Structures    ****
 * ****************************************************************************
 **/
#ifdef STATIC_ARP
#define STATIC_ARP_FILE "../config/static_arp.cfg"
#endif	/* STATIC_ARP */

/* VS: buffers */
char ipAddr[128];
char gwAddr[128];
char netMask[128];
int gatway_flag = 0;
int netlink_sock = -1;

/* print arp table */
static void print_arp_table(void);
/* memory pool for mngt pkts */
extern struct rte_mempool *mngt_ulmp;
extern struct rte_mempool *mngt_dlmp;
/* Rings for management responses (ARP, GTP ECHO, etc...) */
extern struct rte_ring *mngt_ul_ring;
extern struct rte_ring *mngt_dl_ring;

/* hash params */
static struct rte_hash_parameters
	arp_hash_params[NUM_SPGW_PORTS] = {
		{	.name = "ARP_S1U",
			.entries = 64*64,
			.reserved = 0,
			.key_len =
					sizeof(uint32_t),
			.hash_func = rte_jhash,
			.hash_func_init_val = 0 },
		{
			.name = "ARP_SGI",
			.entries = 64*64,
			.reserved = 0,
			.key_len =
					sizeof(uint32_t),
			.hash_func = rte_jhash,
			.hash_func_init_val = 0 }
};
/**
 * rte hash handler.
 */
/* 2 hash handles, one for S1U and another for SGI */
struct rte_hash *arp_hash_handle[NUM_SPGW_PORTS];

/* ****************************************************************************
 * ****    Mngt Handler Utility Functions  ****
 * ****************************************************************************
 **/
static int
parse_ether_addr(struct ether_addr *hw_addr, const char *str)
{
	int ret = sscanf(str, "%"SCNx8":"
			"%"SCNx8":"
			"%"SCNx8":"
			"%"SCNx8":"
			"%"SCNx8":"
			"%"SCNx8,
			&hw_addr->addr_bytes[0],
			&hw_addr->addr_bytes[1],
			&hw_addr->addr_bytes[2],
			&hw_addr->addr_bytes[3],
			&hw_addr->addr_bytes[4],
			&hw_addr->addr_bytes[5]);
	return ret - RTE_DIM(hw_addr->addr_bytes);
}

void
print_arp_table(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;

	uint8_t port_cnt = 0;
	for (; port_cnt < NUM_SPGW_PORTS; ++port_cnt) {
		while (
				rte_hash_iterate(
							arp_hash_handle[port_cnt],
							&next_key, &next_data, &iter
							) >= 0) {

			struct arp_entry_data *tmp_arp_data =
					(struct arp_entry_data *)next_data;
			struct arp_ipv4_key tmp_arp_key;

			memcpy(&tmp_arp_key, next_key,
					sizeof(struct arp_ipv4_key));
			printf("\t%02X:%02X:%02X:%02X:%02X:%02X  %10s  %s\n",
					tmp_arp_data->eth_addr.addr_bytes[0],
					tmp_arp_data->eth_addr.addr_bytes[1],
					tmp_arp_data->eth_addr.addr_bytes[2],
					tmp_arp_data->eth_addr.addr_bytes[3],
					tmp_arp_data->eth_addr.addr_bytes[4],
					tmp_arp_data->eth_addr.addr_bytes[5],
					tmp_arp_data->status == COMPLETE ? "COMPLETE" : "INCOMPLETE",
					inet_ntoa(
						*((struct in_addr *)(&tmp_arp_data->ip))));
		}
	}
}

/* ****************************************************************************
 * ****    ARP Hash Table, Queue/Sent Unresolved pkts functions    ****
 * ****************************************************************************
 **/

/**
 * Add entry in ARP table.
 *
 * @param arp_key
 *	key.
 * @param ret_arp_data
 * @param portid
 * port
 *	return void.
 *
 */
static void add_arp_data(
			struct arp_ipv4_key *arp_key,
			struct arp_entry_data *ret_arp_data, uint8_t portid) {
	int ret;
	/* ARP Entry not present. Add ARP Entry */
	ret = rte_hash_add_key_data(arp_hash_handle[portid],
					&(arp_key->ip), ret_arp_data);
	if (ret) {
		/* Add arp_data panic because:
		 * ret == -EINVAL &&  wrong parameter ||
		 * ret == -ENOSPC && hash table size insufficient
		 * */
		rte_panic("ARP: Error at:%s::"
				"\n\tadd arp_data= %s"
				"\n\tError= %s\n",
				__func__,
				inet_ntoa(*(struct in_addr *)&arp_key->ip),
				rte_strerror(abs(ret)));
	}
}

struct arp_entry_data *
retrieve_arp_entry(struct arp_ipv4_key arp_key,
		uint8_t portid)
{
	int ret;
	struct arp_entry_data *ret_arp_data = NULL;
	struct RouteInfo *route_entry = NULL;
	if (ARPICMP_DEBUG)
		printf("%s::"
				"\n\tretrieve_arp_entry for ip 0x%x\n",
				__func__, arp_key.ip);

	ret = rte_hash_lookup_data(arp_hash_handle[portid],
					&arp_key.ip, (void **)&ret_arp_data);
	if (ret < 0) {
		/* Compute the key(subnet) based on netmask is 24 */
		struct RouteInfo key;
		key.dstAddr = (arp_key.ip & NETMASK);

		ret = rte_hash_lookup_data(route_hash_handle,
						&key.dstAddr, (void **)&route_entry);


		if (ret == 0) {
			if ((route_entry->gateWay != 0) && (route_entry->gateWay_Mac.addr_bytes != 0)) {
				/* Fill the gateway entry */
				ret_arp_data =
						rte_malloc_socket(NULL,
								sizeof(struct arp_entry_data),
								RTE_CACHE_LINE_SIZE, rte_socket_id());
				ret_arp_data->last_update = time(NULL);
				ret_arp_data->status = COMPLETE;
				ret_arp_data->ip = route_entry->gateWay;
				ret_arp_data->eth_addr = route_entry->gateWay_Mac;
				return ret_arp_data;

			} else if ((route_entry->gateWay != 0) && (route_entry->gateWay_Mac.addr_bytes == 0)) {
				struct arp_ipv4_key gw_arp_key;
				gw_arp_key.ip = route_entry->gateWay;
				RTE_LOG_DP(INFO, DP, "GateWay ARP entry not found for %s!!!\n",
						inet_ntoa(*((struct in_addr *)&gw_arp_key.ip)));
				/* No arp entry for arp_key.ip
				 * Add arp_data for arp_key.ip at
				 * arp_hash_handle[portid]
				 * */
				ret_arp_data =
						rte_malloc_socket(NULL,
								sizeof(struct arp_entry_data),
								RTE_CACHE_LINE_SIZE, rte_socket_id());
				ret_arp_data->last_update = time(NULL);
				ret_arp_data->status = INCOMPLETE;
				add_arp_data(&gw_arp_key, ret_arp_data, portid);

				/* Added arp_data for gw_arp_key.ip at
				 * arp_hash_handle[portid]
				 * Queue arp_data in arp_pkt mbuf
				 * send_arp_req(portid, gw_arp_key.ip)
				 * */
				ret_arp_data->ip = gw_arp_key.ip;
				return ret_arp_data;
			}
		}

		RTE_LOG_DP(INFO, DP, "ARP entry not found for %s!!!\n",
				inet_ntoa(*((struct in_addr *)&arp_key.ip)));
		/* No arp entry for arp_key.ip
		 * Add arp_data for arp_key.ip at
		 * arp_hash_handle[portid]
		 * */
		ret_arp_data =
				rte_malloc_socket(NULL,
						sizeof(struct arp_entry_data),
						RTE_CACHE_LINE_SIZE, rte_socket_id());
		ret_arp_data->last_update = time(NULL);
		ret_arp_data->status = INCOMPLETE;
		add_arp_data(&arp_key, ret_arp_data, portid);

		/* Added arp_data for arp_key.ip at
		 * arp_hash_handle[portid]
		 * Queue arp_data in arp_pkt mbuf
		 * send_arp_req(portid, arp_key.ip)
		 * */
		ret_arp_data->ip = arp_key.ip;
	}
	return ret_arp_data;
}

/**
 * Update ARP Hash Table.
 *
 * @param hw_addr
 *	source hw_addr.
 * @param ipaddr
 *	source IP address.
 * @param portid
 * port
 *	return void.
 *
 */
static
void update_arp_table(const struct ether_addr *hw_addr,
		uint32_t ipaddr, uint8_t portid)
{
	struct arp_ipv4_key arp_key;
	arp_key.ip = ipaddr;

	if (ARPICMP_DEBUG)
		printf("%s::"
				"\n\tarp_key.ip= 0x%x; portid= %d\n",
				__func__, arp_key.ip, portid);

	/* On ARP_REQ || ARP_RSP retrieve_arp_entry */
	struct arp_entry_data *arp_data =
				retrieve_arp_entry(arp_key, portid);

	if (arp_data) {
		arp_data->last_update = time(NULL);
		if (!(is_same_ether_addr(&arp_data->eth_addr, hw_addr))) {
			/* ARP_RSP || ARP_REQ:
			 * Copy hw_addr -> arp_data->eth_addr
			 * */
			ether_addr_copy(hw_addr, &arp_data->eth_addr);
			if (arp_data->status == INCOMPLETE) {
				arp_data->status = COMPLETE;
			}
		}
	}
}

/**
 * Delete ARP entry in ARP Hash Table.
 *
 * @param ipaddr
 *	source IP address.
 * @param portid
 * port
 *	return void.
 *
 */
static void del_arp_data(uint32_t ipaddr, uint8_t portid)
{
	struct arp_ipv4_key arp_key;
	arp_key.ip = ipaddr;
	struct arp_entry_data *arp_data = retrieve_arp_entry(arp_key, portid);
	if(arp_data)
		rte_free(arp_data);

	int32_t ret = rte_hash_del_key(arp_hash_handle[portid], &ipaddr);
	if (ret < 0){
		RTE_LOG_DP(ERR, DP, "Failed to del entry in ARP hash table");
	}
}

/* ****************************************************************************
 * ****    Mngt Ingress, egress and ARP processing Functions    ****
 * ****************************************************************************
 **/

int mngt_ingress(struct rte_mbuf *pkt, uint8_t in_port_id)
{
	char *mngt_req = rte_pktmbuf_mtod(pkt, char *);
	int pkt_size = rte_pktmbuf_pkt_len(pkt);
	char *mngt_rsp = rte_zmalloc("mngt_resp", (pkt_size + PKT_LEN_SIZE),
					RTE_CACHE_LINE_SIZE);
	/* epc_ul(...)::mngt_ingress(...)::in_port_id == S1U_PORT_ID */
	struct rte_ring *dst_queue = (in_port_id == S1U_PORT_ID) ?
					mngt_dl_ring : mngt_ul_ring;
	if (mngt_rsp) {
		/* Copying pkt len into first four bytes of malloc'd structure */
		((int *)mngt_rsp)[0] = pkt_size;
		/* Copying the packet into malloc'd structure */
		memcpy(&mngt_rsp[PKT_LEN_SIZE], mngt_req, pkt_size);
		if (rte_ring_enqueue(dst_queue, mngt_rsp) == -ENOBUFS) {
			RTE_LOG_DP(ERR, DP, "%s::Can't queue Mngt pkt- ring full..."
				" Dropping pkt\n", __func__);
			rte_free(mngt_rsp);
		}
	}
	return 0;
}

uint16_t mngt_egress(port_pairs_t *ip_op, struct rte_mbuf **pkts)
{
	/* epc_dl(...)::mngt_egress(...)::ip_op->in_pid == SGI_PORT_ID */
	struct rte_ring *dst_queue = (ip_op->in_pid == S1U_PORT_ID) ?
					mngt_ul_ring : mngt_dl_ring;
	struct rte_mempool *mp = (ip_op->in_pid == S1U_PORT_ID) ?
					mngt_ulmp : mngt_dlmp;
	uint32_t queued_cnt = rte_ring_count(dst_queue);
	int i, j = 0, pkt_size;
	char *pkt_buf, *mngt_rsp;
	if (queued_cnt) {
		char *buffs[queued_cnt];
		/* Dequeue malloc'd buffers */
		uint32_t rx_cnt = rte_ring_dequeue_bulk(dst_queue,
				(void**)buffs, queued_cnt, NULL);
		for (i = 0,j = 0; i < rx_cnt; i++) {
			pkt_buf = buffs[i];
			/* Allocate pkt mbuf at port mempool for GTP Echo Response */
			pkts[j] = rte_pktmbuf_alloc(mp);
			if (pkts[j] == NULL) {
				rte_free(pkt_buf);
				rte_panic("Failed to alloc mbuf for mngt resp messages");
			}
			/* convert malloc'd buffer into mbuf */
			pkt_size = ((int *)pkt_buf)[0];
			mngt_rsp = rte_pktmbuf_mtod(pkts[j], char *);
			memcpy(mngt_rsp, &pkt_buf[PKT_LEN_SIZE], pkt_size);
			pkts[j]->pkt_len = pkts[j]->data_len = pkt_size;

			/* Process GTP ECHO REQ */
			process_echo_request(pkts[j]);

			/* Free malloc'd buffer */
			rte_free(pkt_buf);
			j++;
		}
	}
	return j;
}

/* ****************************************************************************
 * ****    Static ARP Table Update/Functions	****
 * ****************************************************************************
 **/

/**
 * Add static ARP entry into ARP Hash.
 *
 * @param entry
 *	static ARP entry.
 * @param port_id
 * port
 *	return void.
 *
 */
#ifdef STATIC_ARP
static void
add_static_arp_entry(struct rte_cfgfile_entry *entry,
			uint8_t port_id)
{
	struct arp_ipv4_key key;
	struct arp_entry_data *data;
	char *low_ptr;
	char *high_ptr;
	char *saveptr;
	struct in_addr low_addr;
	struct in_addr high_addr;
	uint32_t low_ip;
	uint32_t high_ip;
	uint32_t cur_ip;
	struct ether_addr hw_addr;
	int ret;

	low_ptr = strtok_r(entry->name, " \t", &saveptr);
	high_ptr = strtok_r(NULL, " \t", &saveptr);

	if (low_ptr == NULL) {
		printf("Error parsing static arp entry: %s = %s\n",
				entry->name, entry->value);
		return;
	}

	ret = inet_aton(low_ptr, &low_addr);
	if (ret == 0) {
		printf("Error parsing static arp entry: %s = %s\n",
				entry->name, entry->value);
		return;
	}

	if (high_ptr) {
		ret = inet_aton(high_ptr, &high_addr);
		if (ret == 0) {
			printf("Error parsing static arp entry: %s = %s\n",
					entry->name, entry->value);
			return;
		}
	} else {
		high_addr = low_addr;
	}

	low_ip = ntohl(low_addr.s_addr);
	high_ip = ntohl(high_addr.s_addr);

	if (high_ip < low_ip) {
		printf("Error parsing static arp entry"
				" - range must be low to high: %s = %s\n",
				entry->name, entry->value);
		return;
	}

	if (parse_ether_addr(&hw_addr, entry->value)) {
		printf("Error parsing static arp entry mac addr"
				"%s = %s\n",
				entry->name, entry->value);
		return;
	}

	for (cur_ip = low_ip; cur_ip <= high_ip; ++cur_ip) {

		key.ip = ntohl(cur_ip);

		data = rte_malloc_socket(NULL,
				sizeof(struct arp_entry_data),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (data == NULL) {
			printf("Error allocating arp entry - "
					"%s = %s\n",
					entry->name, entry->value);
			return;
		}

		data->eth_addr = hw_addr;
		data->port = port_id;
		data->status = COMPLETE;
		data->ip = key.ip;
		data->last_update = time(NULL);

		add_arp_data(&key, data, port_id);
	}
}

/**
 * Configure Static ARP Entries.
 *	return void.
 */
static void
config_static_arp(void)
{
	struct rte_cfgfile *file = rte_cfgfile_load(STATIC_ARP_FILE, 0);
	struct rte_cfgfile_entry *sgi_entries = NULL;
	struct rte_cfgfile_entry *s1u_entries = NULL;
	int num_sgi_entries;
	int num_s1u_entries;
	int i;

	if (file == NULL) {
		printf("Cannot load configuration file %s\n",
				STATIC_ARP_FILE);
		return;
	}

	printf("Parsing %s\n", STATIC_ARP_FILE);

	num_sgi_entries = rte_cfgfile_section_num_entries(file, "sgi");
	if (num_sgi_entries > 0) {
		sgi_entries = rte_malloc_socket(NULL,
				sizeof(struct rte_cfgfile_entry) *
				num_sgi_entries,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	}
	if (sgi_entries == NULL) {
		fprintf(stderr, "Error configuring sgi entry of %s\n",
				STATIC_ARP_FILE);
	} else {
		rte_cfgfile_section_entries(file, "sgi", sgi_entries,
				num_sgi_entries);

		for (i = 0; i < num_sgi_entries; ++i) {
			printf("[SGI]: %s = %s\n", sgi_entries[i].name,
					sgi_entries[i].value);
			add_static_arp_entry(&sgi_entries[i], SGI_PORT_ID);
		}
		rte_free(sgi_entries);
	}

	num_s1u_entries = rte_cfgfile_section_num_entries(file, "s1u");
	if (num_s1u_entries > 0) {
		s1u_entries = rte_malloc_socket(NULL,
				sizeof(struct rte_cfgfile_entry) *
				num_s1u_entries,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	}
	if (s1u_entries == NULL) {
		fprintf(stderr, "Error configuring s1u entry of %s\n",
				STATIC_ARP_FILE);
	} else {
		rte_cfgfile_section_entries(file, "s1u", s1u_entries,
				num_s1u_entries);
		for (i = 0; i < num_sgi_entries; ++i) {
			printf("[S1u]: %s = %s\n", s1u_entries[i].name,
					s1u_entries[i].value);
			add_static_arp_entry(&s1u_entries[i], S1U_PORT_ID);
		}
		rte_free(s1u_entries);
	}

	if (ARPICMP_DEBUG)
		print_arp_table();
}
#endif	/* STATIC_ARP */

/* ****************************************************************************
 * ****    Route Table Update/Mngt functions/netlink functions	  ****
 * ****************************************************************************
 **/

/**
 * Print route entry information
 */
static int print_route_entry(
		struct RouteInfo *entry)
{
		/* VS:	Print the route records on cosole */
		printf("-----------\t------- \t--------\t------\t------ \n");
		printf("Destination\tGateway \tNetmask \tflags \tIfname \n");
		printf("-----------\t------- \t--------\t------\t------ \n");

		struct in_addr IP_Addr, GW_Addr, Net_Mask;
		IP_Addr.s_addr = entry->dstAddr;
		GW_Addr.s_addr = entry->gateWay;
		Net_Mask.s_addr = ntohl(entry->mask);

		strncpy(ipAddr, inet_ntoa(IP_Addr), sizeof(ipAddr));
		strncpy(gwAddr, inet_ntoa(GW_Addr), sizeof(gwAddr));
		strncpy(netMask, inet_ntoa(Net_Mask), sizeof(netMask));

		printf("%s	\t%8s\t%8s \t%u \t%s\n",
				ipAddr, gwAddr, netMask,
				entry->flags,
				entry->ifName);

		printf("-----------\t------- \t--------\t------\t------ \n");
		return 0;
}

/**
 * Delete entry in route table.
 *
 * @param rte_route_data
 *		- key
 *		- route info
 * port
 *	return void.
 *
 */
static int
del_route_entry(
			struct RouteInfo *info)
{
	int ret;
	struct RouteInfo *ret_route_data = NULL;

	/* Check Route Entry is present or Not */
	ret = rte_hash_lookup_data(route_hash_handle,
					&info->dstAddr, (void **)&ret_route_data);
	if (ret) {
		/* Route Entry is present. Delete Route Entry */
		ret = rte_hash_del_key(route_hash_handle, &info->dstAddr);
		if (ret < 0) {
			rte_panic("ROUTE: Error at:%s::"
					"\n\tDelete route_data= %s"
					"\n\tError= %s\n",
					__func__,
					inet_ntoa(*(struct in_addr *)&info->dstAddr),
					rte_strerror(abs(ret)));


			return -1;
		}

		printf("Route entry DELETED from hash table :: \n");
		print_route_entry(info);
	}
	return 0;

}

/**
 * Add entry in route table.
 *
 * @param rte_route_data
 *		- key
 *		- route info
 * port
 *	return void.
 *
 */
static void add_route_data(
			struct RouteInfo *info) {
	int ret;
	struct RouteInfo *ret_route_data = NULL;

	/* Check Route Entry is present or Not */
	ret = rte_hash_lookup_data(route_hash_handle,
					&info->dstAddr, (void **)&ret_route_data);
	if (ret < 0) {

		/* Route Entry not present. Add Route Entry */
		if (gatway_flag != 1) {
			info->gateWay = 0;
			memset(&info->gateWay_Mac, 0, sizeof(struct ether_addr));
		}

		ret = rte_hash_add_key_data(route_hash_handle,
						&info->dstAddr, info);
		if (ret) {
			/* Add route_data panic because:
			 * ret == -EINVAL &&  wrong parameter ||
			 * ret == -ENOSPC && hash table size insufficient
			 * */
			rte_panic("ROUTE: Error at:%s::"
					"\n\tadd route_data= %s"
					"\n\tError= %s\n",
					__func__,
					inet_ntoa(*(struct in_addr *)&info->dstAddr),
					rte_strerror(abs(ret)));
		}

		gatway_flag = 0;

		printf("Route entry ADDED in hash table :: \n");
		print_route_entry(info);
		return;
	} else if (ret == 0) {
		if (ret_route_data->dstAddr == info->dstAddr){

			/* Route Entry not present. Add Route Entry */
			if (gatway_flag != 1) {
				info->gateWay = 0;
				memset(&info->gateWay_Mac, 0, sizeof(struct ether_addr));
			}

			ret = rte_hash_add_key_data(route_hash_handle,
							&info->dstAddr, info);
			if (ret) {
				/* Add route_data panic because:
				 * ret == -EINVAL &&  wrong parameter ||
				 * ret == -ENOSPC && hash table size insufficient
				 * */
				rte_panic("ROUTE: Error at:%s::"
						"\n\tadd route_data= %s"
						"\n\tError= %s\n",
						__func__,
						inet_ntoa(*(struct in_addr *)&info->dstAddr),
						rte_strerror(abs(ret)));
			}

			gatway_flag = 0;

			printf("Route entry ADDED in hash table :: \n");
			print_route_entry(info);
			return;
		}

	}
	print_route_entry(ret_route_data);
}

/**
 * Get the interface name based on interface index.
 */

static int
get_iface_name(int iface_index, char *iface_Name)
{
	int fd;
	struct ifreq ifr;


	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd == -1)
	{
		perror("socket");
		exit(1);
	}

	ifr.ifr_ifindex = iface_index;

	if(ioctl(fd, SIOCGIFNAME, &ifr, sizeof(ifr)))
	{
		perror("ioctl");
		return -1;
	}
	strcpy(iface_Name, ifr.ifr_name);
	close(fd);
	return 0;
}

static int readCache(int Fd, char *Buffer)
{
	if (Fd < 0)
	{
		return -1;
	}

	char ch;
	size_t Read = 0;

	while (read(Fd, (Buffer + Read), 1))
	{
		ch = Buffer[Read];
		if (ch == '\n')
		{
			break;
		}
		Read++;
	}

	if (Read)
	{
		Buffer[Read] = 0;
		return 0;
	}
	return -1;
}

static char *getField(char *Line_Arg, int Field)
{
	char *ret;
	char *s;

	char *Line = malloc(strlen(Line_Arg) + 1), *ptr;
	memset(Line, 0, strlen(Line_Arg) + 1);
	memcpy(Line, Line_Arg, strlen(Line_Arg));
	ptr = Line;

	s = strtok(Line, ARP_DELIM);
	while (Field && s)
	{
		s = strtok(NULL, ARP_DELIM);
		Field--;
	};

	if (s)
	{
		ret = (char*)malloc(strlen(s) + 1);
		memset(ret, 0, strlen(s) + 1);
		memcpy(ret, s, strlen(s));
	}
	free(ptr);

	return s ? ret : NULL;
}

/**
 * Get the Gateway MAC Address from ARP TABLE.
 */
static int
get_gateWay_mac(uint32_t IP_gateWay, char *iface_Mac)
{
	int Fd = open(ARP_CACHE, O_RDONLY);

	if (Fd < 0)
	{
		fprintf(stdout, "Arp Cache: Failed to open file \"%s\"\n", ARP_CACHE);
		return 1;
	}

	char Buffer[ARP_BUFFER_LEN];

	/* Ignore first line */
	int Ret = readCache(Fd, &Buffer[0]);

	Ret = readCache(Fd, &Buffer[0]);
	//int count = 0;

	while (Ret == 0)
	{
		char *Line;
		Line = &Buffer[0];

		/* Get Ip, Mac, Interface */
		char *Ip		= getField(Line, 0);
		char *Mac		= getField(Line, 3);
		char *IfaceStr	= getField(Line, 5);

		char *tmp = inet_ntoa(*(struct in_addr *)&IP_gateWay);
		if (strcmp(Ip, tmp) == 0) {
			//fprintf(stdout, "%03d: here, Mac Address of [%s] on [%s] is \"%s\"\n",
			//		  ++count, Ip, IfaceStr, Mac);

			strcpy(iface_Mac, Mac);
			return 0;
		}

		free(Ip);
		free(Mac);
		free(IfaceStr);

		Ret = readCache(Fd, &Buffer[0]);
	}
	close(Fd);
	return 0;
}

/**
 * Create pthread to read or receive data/events from netlink socket.
 */
static void
*netlink_recv_thread(void *arg)
{

	int		recv_bytes = 0;
	int		count = 0, i;
	struct	nlmsghdr *nlp;
	struct	rtmsg *rtp = NULL;
	struct  ndmsg *ntp = NULL;
	struct	RouteInfo route[24];
	struct	rtattr *rtap;
	int		rtl = 0;
	char	buffer[BUFFER_SIZE];
	char ifName[IFACE_NAME_LEN];
	uint32_t dst_addr = 0;
	uint8_t mac_addr[ETH_ALEN];
	uint8_t portid = 0;

	bzero(buffer, sizeof(buffer));

	struct sockaddr_nl *addr = (struct sockaddr_nl *)arg;
	while(1)
	{

		/* VS: Receive data pkts from netlink socket*/
		while (1)
		{
			bzero(buffer, sizeof(buffer));

			recv_bytes = recv(netlink_sock, buffer, sizeof(buffer), 0);
			if (recv_bytes < 0)
				printf("Error in recv\n");

			nlp = (struct nlmsghdr *) buffer;
			if ((nlp->nlmsg_type == NLMSG_DONE)   ||
				(nlp->nlmsg_type == RTM_NEWROUTE) ||
				(nlp->nlmsg_type == RTM_DELROUTE) ||
				(nlp->nlmsg_type == RTM_NEWNEIGH) ||
				(nlp->nlmsg_type == RTM_DELNEIGH) ||
				(addr->nl_groups == RTMGRP_IPV4_ROUTE))
				break;
		}

		for (i = -1 ; NLMSG_OK(nlp, recv_bytes); \
						nlp = NLMSG_NEXT(nlp, recv_bytes))
		{
			if ((nlp->nlmsg_type == RTM_NEWNEIGH) ||
					(nlp->nlmsg_type == RTM_DELNEIGH))
			{
				ntp = (struct ndmsg *) NLMSG_DATA(nlp);
				if (get_iface_name(ntp->ndm_ifindex, ifName) != -1); {
					if (!strcmp(app.ul_iface_name, ifName))
						portid = S1U_PORT_ID;
					else if (!strcmp(app.dl_iface_name, ifName))
						portid = SGI_PORT_ID;
					else
						continue;
					if (ARPICMP_DEBUG)
						printf("Interface Name:[%s]-index:[%d]\n",ifName, ntp->ndm_ifindex);
				}
				/* Get attributes of ntp */
				rtap = (struct rtattr *) RTM_RTA(ntp);
			} else {
				rtp = (struct rtmsg *) NLMSG_DATA(nlp);
				/* Get main routing table */
				if ((rtp->rtm_family != AF_INET) ||
						(rtp->rtm_table != RT_TABLE_MAIN))
					continue;
				/* Get attributes of rtp */
				rtap = (struct rtattr *) RTM_RTA(rtp);

				i++;
				route[i].flags|=RTF_UP;
			}

			/* Get the route atttibutes len */
			rtl = RTM_PAYLOAD(nlp);

			/* Loop through all attributes */
			for( ; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl))
			{
					switch(rtap->rta_type)
					{
						/* Get the destination IPv4 address */
						case RTA_DST:
							if ((nlp->nlmsg_type == RTM_NEWNEIGH) ||
									(nlp->nlmsg_type == RTM_DELNEIGH))
							{
								dst_addr = *(uint32_t *) RTA_DATA(rtap);
								if (ARPICMP_DEBUG)
									printf("RTA_DST:[%s]\n",inet_ntoa(*(struct in_addr *)&dst_addr));
							} else {
								count = 32 - rtp->rtm_dst_len;

								route[i].dstAddr = *(uint32_t *) RTA_DATA(rtap);

								route[i].mask = 0xffffffff;
								for (; count!=0 ;count--)
									route[i].mask = route[i].mask << 1;

								if (route[i].mask == 0xFFFFFFFF)
									route[i].flags|=RTF_HOST;
							}
							break;

						case RTA_GATEWAY:
								gatway_flag = 1;
								char mac[64];

								route[i].gateWay = *(uint32_t *) RTA_DATA(rtap);
								get_gateWay_mac(route[i].gateWay, mac);

								if (parse_ether_addr(&(route[i].gateWay_Mac), mac)) {
									printf("Error parsing gatway arp entry mac addr"
											"= %s\n",
											mac);

								}

								if (route[i].gateWay != 0)
									route[i].flags|=RTF_GATEWAY;

								fprintf(stdout, "Gateway, Mac Address of [%s] is \"%02X:%02X:%02X:%02X:%02X:%02X\"\n",
										inet_ntoa(*(struct in_addr *)&route[i].gateWay),
										route[i].gateWay_Mac.addr_bytes[0],
										route[i].gateWay_Mac.addr_bytes[1],
										route[i].gateWay_Mac.addr_bytes[2],
										route[i].gateWay_Mac.addr_bytes[3],
										route[i].gateWay_Mac.addr_bytes[4],
										route[i].gateWay_Mac.addr_bytes[5]);
								break;

						case RTA_PREFSRC:
							route[i].srcAddr = *(uint32_t *) RTA_DATA(rtap);
							break;

						case RTA_OIF:
							if ((nlp->nlmsg_type != RTM_NEWNEIGH) &&
									(nlp->nlmsg_type != RTM_DELNEIGH)) {
								if (*((int *) RTA_DATA(rtap)))
									get_iface_name(*((int *) RTA_DATA(rtap)),
											route[i].ifName);
							}
							break;

						case NDA_LLADDR:
							bzero(mac_addr, ETH_ALEN);
							memcpy(mac_addr, RTA_DATA(rtap), ETH_ALEN);
							if (ARPICMP_DEBUG)
								printf("NDA_LLADDR:\"%02X:%02X:%02X:%02X:%02X:%02X\"\n",
									mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
							break;

						default:
							break;
					}
			}

			switch(nlp->nlmsg_type)
			{
				case RTM_NEWROUTE:
					add_route_data(&route[i]);
					break;
				case RTM_DELROUTE:
					del_route_entry(&route[i]);
					break;
				case RTM_NEWNEIGH:
					update_arp_table((struct ether_addr *)mac_addr,
							dst_addr, portid);
					break;
				case RTM_DELNEIGH:
					del_arp_data(dst_addr, portid);
					break;
				default:
					break;
			}
		}
	}
	return NULL; //GCC_Security flag
}

/**
 * Initialize netlink socket.
 */
static int
init_netlink_socket(void)
{
	int retValue = -1;
	struct sockaddr_nl addr_t;

	route_request *request =
		(route_request *)malloc(sizeof(route_request));

	netlink_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	bzero(request,sizeof(route_request));

	/* Fill the NETLINK header */
	request->nlMsgHdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	request->nlMsgHdr.nlmsg_type = RTM_GETROUTE;
	//request->nlMsgHdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request->nlMsgHdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

	/* set the routing message header */
	request->rtMsg.rtm_family = AF_INET;
	request->rtMsg.rtm_table = RT_TABLE_MAIN;

	addr_t.nl_family = PF_NETLINK;
	addr_t.nl_pad = 0;
	addr_t.nl_pid = getpid();
	addr_t.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTM_NEWNEIGH;

	if (bind(netlink_sock,(struct sockaddr *)&addr_t,sizeof(addr_t)) < 0)
		ERR_RET("bind socket");

	/* Send routing request */
	if ((retValue = send(netlink_sock, request, sizeof(route_request), 0)) < 0)
	{
		perror("send");
		return -1;
	}

	/*
	 * Create pthread to read or receive data/events from netlink socket.
	 */
	pthread_t net;
	int err_val;

	err_val = pthread_create(&net, NULL, &netlink_recv_thread, &addr_t);
	if (err_val != 0) {
		fprintf(stderr, "\nAPI: Can't create Netlink socket event reader thread :[%s]\n",
				strerror(err_val));
		return -1;
	} else {
		fprintf(stderr, "\nAPI: Netlink socket event reader thread "
				"created successfully...!!!\n");
	}

	return 0;
}

/* ****************************************************************************
 * ****    Mngt Handler Initialization	****
 * ****************************************************************************
 **/
/**
 * Initialize Mngt Plane Handler.
 */
void
mngtplane_init(void)
{
	uint8_t port_cnt;

	for (port_cnt = 0; port_cnt < NUM_SPGW_PORTS; ++port_cnt) {
		/* Create arp_hash for each port */
		arp_hash_params[port_cnt].socket_id = rte_socket_id();
		arp_hash_handle[port_cnt] =
				rte_hash_create(&arp_hash_params[port_cnt]);
		if (!arp_hash_handle[port_cnt]) {
			rte_panic("%s::"
					"\n\thash create failed::"
					"\n\trte_strerror= %s; rte_errno= %u\n",
					arp_hash_params[port_cnt].name,
					rte_strerror(rte_errno),
					rte_errno);
		}
	}

	/**
	 * VS: Routing Discovery
	 */

#ifndef STATIC_ARP
	if (init_netlink_socket() != 0)
		rte_exit(EXIT_FAILURE, "Cannot init netlink socket...!!!\n");
#else
	config_static_arp();
#endif	/* STATIC_ARP */
}

