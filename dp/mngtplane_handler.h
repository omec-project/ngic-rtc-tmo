/*
 * Copyright (c) 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __MNGT_PLANE_HANDLER_H__
#define __MNGT_PLANE_HANDLER_H__
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of ARP packet processing.
 */
#include <rte_ether.h>
#include <rte_rwlock.h>

/* VS: Routing Discovery */
#include <fcntl.h>
#include "linux/netlink.h"
#include "linux/rtnetlink.h"
#include "net/if.h"
#include "net/if_arp.h"
#include "sys/ioctl.h"
#include "net/route.h"
#include "ngic_rtc_framework.h"

/* seconds between ARP request retransmission */
#define ARP_TIMEOUT 2

/* ring size */
#define ARP_BUFFER_RING_SIZE 512

/* ARP entry populated and echo reply received */
#define COMPLETE   1

/* ARP entry populated and awaiting ARP reply */
#define INCOMPLETE 0

/* set to enable debug */
#define ARPICMP_DEBUG 0

/* netlink_recv_thread buffer */
#define BUFFER_SIZE 4096

/* size of packet length indicator */
#define PKT_LEN_SIZE 4

/* ETH Address Length */
#define ETH_ALEN 6

/* Ring name length */
#define RING_NAME_LEN 16

/* Interface name Length */
#define IFACE_NAME_LEN 32

/* print mac format */
#define FORMAT_MAC  \
	"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8

/* print eth_addr */
#define FORMAT_MAC_ARGS(eth_addr)  \
	(eth_addr).addr_bytes[0],  \
(eth_addr).addr_bytes[1],  \
(eth_addr).addr_bytes[2],  \
(eth_addr).addr_bytes[3],  \
(eth_addr).addr_bytes[4],  \
(eth_addr).addr_bytes[5]

#if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
/* x86 == little endian
 * network	== big endian
 */
#define CHECK_ENDIAN_16(x) rte_be_to_cpu_16(x)
#define CHECK_ENDIAN_32(x) rte_be_to_cpu_32(x)
#else
#define CHECK_ENDIAN_16(x) (x)
#define CHECK_ENDIAN_32(x) (x)
#endif

/* VS: Routing Discovery */
#define NETMASK ntohl(4294967040)
#define ERR_RET(x) do { perror(x); return EXIT_FAILURE; } while (0);

/* VS: Get Local arp table entry */
#define ARP_CACHE		"/proc/net/arp"
#define ARP_BUFFER_LEN	1024
#define ARP_DELIM		" "

/* Structure for sending the request */
typedef struct
{
	struct nlmsghdr nlMsgHdr;
	struct rtmsg rtMsg;
	char buf[4096];
}route_request;

/* Structure for storing routes */
struct RouteInfo
{
	uint32_t dstAddr;
	uint32_t mask;
	uint32_t gateWay;
	uint32_t flags;
	uint32_t srcAddr;
	char proto;
	char ifName[IF_NAMESIZE];
	/** mac address */
	struct ether_addr gateWay_Mac;
};

/* IPv4 key for ARP table. */
struct arp_ipv4_key {
	/** ipv4 address */
	uint32_t ip;
};

/* arp port address */
struct arp_port_address {
	/** ipv4 address*/
	uint32_t ip;
	/** mac address */
	struct ether_addr *mac_addr;
};

/* ARP table entry */
struct arp_entry_data {
	/** ipv4 address */
	uint32_t ip;
	/** ether address */
	struct ether_addr eth_addr;
	/** status: COMPLETE/INCOMPLETE */
	uint8_t status;
	/** last update time */
	time_t last_update;
	/** UL || DL port id */
	uint8_t port;
} __attribute__((packed));

/**
 * Retrieve ARP entry.
 *
 * @param arp_key
 *	key.
 * @param portid
 *	port id
 *
 * @return
 *	arp entry data if found.
 *	neg value if error.
 */
struct arp_entry_data *retrieve_arp_entry(
			const struct arp_ipv4_key arp_key,
			uint8_t portid);

/**
 * Send Mngt Messages to crossover core.
 *
 * @param pkt
 *	Req/Rsp packet
 * @param in_port_id
 *	port id
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int mngt_ingress(struct rte_mbuf *pkt, uint8_t in_port_id);
/**
 * DeQueue Mngt Responses and Sent.
 *
 * @param ip_op
 *	in/out port data.
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
uint16_t mngt_egress(port_pairs_t *ip_op, struct rte_mbuf **pkts);
#endif /*__MNGT_PLANE_HANDLER_H__ */
