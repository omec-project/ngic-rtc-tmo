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

#ifndef _PKT_PROC_H_
#define _PKT_PROC_H_

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_log.h>

#include "main.h"

/* ****************************************************************************
 * ****    Unit Test Defines    ****
 * ****************************************************************************
 **/

#define ARP_MSG_SIZE 60

/* ****************************************************************************
 * ****    Unit Test Function Prototypes    ****
 * ****************************************************************************
 **/

/**
 * Function to manipulate mixed packets.
 *
 * @param pkts
 * Received packets.
 * @n
 * Number of packets received
 * @port_id
 * Port Id
 * @return
 * None
 */

void create_mixed_bursts(struct rte_mbuf **pkts, uint32_t n, uint8_t port_id);
#endif
