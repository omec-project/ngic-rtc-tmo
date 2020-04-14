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

#ifndef _INTERFACE_H_
#define _INTERFACE_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of CP/DP module constructor and communication interface type.
 */
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <rte_hash.h>

#ifdef SDN_ODL_BUILD
	#include "zmqsub.h"
#endif /* SDN_ODL_BUILD  */

#include "cp_dp_api.h"

uint8_t zmq_comm_switch;

char zmq_pull_ifconnect[128];
char zmq_push_ifconnect[128];

extern struct in_addr zmq_cp_ip, zmq_dp_ip;
extern uint16_t zmq_cp_pull_port, zmq_dp_pull_port;
extern uint16_t zmq_cp_push_port, zmq_dp_push_port;
extern struct rte_hash *resp_op_id_hash;

#ifdef SDN_ODL_BUILD
char zmq_sub_ifconnect[128];
char zmq_pub_ifconnect[128];

extern struct in_addr fpc_ip;
extern uint16_t fpc_port;
extern uint16_t fpc_topology_port;
extern struct in_addr cp_nb_ip;
extern uint16_t cp_nb_port;
#endif

/* DP zmq_mbuf_push("cdr_ring", ...) over interface */
#ifdef DP_BUILD
extern struct rte_ring *cdr_ring;
#endif /* DP_BUILD */

/* CP DP communication message type*/
enum cp_dp_comm {
	COMM_QUEUE,    /* ASR-Reserved Future Use (RFU) */
	COMM_SOCKET,   /* ASR-Reserved Future Use (RFU) */
	COMM_ZMQ,
	COMM_END,
};
/**
 * CP DP Communication message structure.
 */
struct comm_node {
	int status;					/*set if initialized*/
	int (*init)(void);				/*init function*/
	int (*send)(void *msg_payload, uint32_t size);	/*send function*/
	int (*recv)(void *msg_payload, uint32_t size);	/*receive function*/
	int (*destroy)(void);			/*uninit and free function*/
};
struct comm_node comm_node[COMM_END];
struct comm_node *active_comm_msg;


/**
 * Registor CP DP Communication message type.
 * @param id
 *	id - identifier for type of communication.
 * @param  init
 *	init - initialize function.
 * @param  send
 *	send - send function.
 * @param  recv
 *	recv - receive function.
 * @param  destroy
 *	destroy - destroy function.
 *
 * @return
 *	None
 */
void register_comm_msg_cb(enum cp_dp_comm id,
		int (*init)(void),
		int (*send)(void *msg_payload, uint32_t size),
		int (*recv)(void *msg_payload, uint32_t size),
		int (*destroy)(void));

/**
 * Set CP DP Communication type.
 * @param id
 *	id - identifier for type of communication.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
int set_comm_type(enum cp_dp_comm id);
/**
 * Unset CP DP Communication type.
 * @param id
 *	id - identifier for type of communication.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
int unset_comm_type(enum cp_dp_comm id);
/**
 * Process CP DP Communication msg type.
 * @param buf
 *	buf - message buffer.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
int process_comm_msg(void *buf);

/**
 * Process DP Response
 * @param buf
 *	buf - message buffer.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
int process_dp_resp(void *buf);

/**
 * @brief Initialize iface message passing
 *
 * This function is not thread safe and should only be called once by DP.
 */
void iface_module_constructor(void);

/**
 * @brief DP::process queued CDR records
 * DP::zmq_mbuf_push("cdr_ring", ...) over interface
 * This function is not thread safe and should only be called once by DP.
 */
int process_cdr_queue(void);

/**
 * @brief Initialize secure CTF interface
 *
 * This function is not thread safe and should only be called once by CP.
 */
void init_sctf(void);

/**
 * Writing CDR record to SSL connection.
 */
void write_sctf(uint8_t *der, uint16_t der_len);

/**
 * Close the CDR ssl connection.
 *
 */
void close_sctf(void);

/**
 * @brief Functino to handle signals.
 */
void sig_handler(int signo);

#endif /* _INTERFACE_H_ */
