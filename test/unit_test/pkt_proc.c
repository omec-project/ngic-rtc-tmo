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

#include "pkt_proc.h"

/* ****************************************************************************
 * ****    Unit Test Data Initialization    ****
 * ****************************************************************************
 **/

/*
 * Simulated packets initialized here. Procedure's used to initialize the
 * packets are below,
 * Option 1: Collect the packet hex dump from existing pcap file
 * Option 2: Use following gdb procedure to collect the hex dump,
 *
 *    a. set break point after rte_eth_rx_burst() at epc_ul.c/epc_dl.c
 *    b. print the required packet using below command (use appropriate
 *       mbuf parameter),
 *       p/x *((char *)m->buf_addr + m->data_off)@m->data_len
 */

/* ARP Request on S1U */
char s1u_arp_req[ARP_MSG_SIZE] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3c, 0xfd,
	0xfe, 0x9e, 0x64, 0xb9, 0x08, 0x06, 0x00, 0x01,
	0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x3c, 0xfd,
	0xfe, 0x9e, 0x64, 0xb9, 0x0b, 0x07, 0x01, 0x65,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x07,
	0x01, 0x5d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
	};

/* ARP Request on SGI */
char sgi_arp_req[ARP_MSG_SIZE] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3c, 0xfd,
	0xfe, 0x9e, 0x64, 0xba, 0x08, 0x06, 0x00, 0x01,
	0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x3c, 0xfd,
	0xfe, 0x9e, 0x64, 0xba, 0x0d, 0x07, 0x01, 0x6e,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x07,
	0x01, 0x5d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
	};

/* ****************************************************************************
 * ****    Unit Test Functions    ****
 * ****************************************************************************
 **/

void create_mixed_bursts(struct rte_mbuf **pkts, uint32_t n, uint8_t port_id)
{
	char *pkt_data_ptr = NULL;
	char *msg2cpy = (port_id == S1U_PORT_ID) ? s1u_arp_req : sgi_arp_req;
	for(int i = 0; i < n; i++)
	{
		if(i%2 != 0) {
			pkt_data_ptr = rte_pktmbuf_mtod(pkts[i], char *);
			memcpy(pkt_data_ptr, msg2cpy, ARP_MSG_SIZE);
			pkts[i]->pkt_len = pkts[i]->data_len = ARP_MSG_SIZE;
		}

	}
}

