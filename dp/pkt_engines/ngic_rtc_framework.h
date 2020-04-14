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

#ifndef __EPC_PACKET_FRAMEWORK_H__
#define __EPC_PACKET_FRAMEWORK_H__

/**
 * @file
 * This file contains data structure definitions to describe
 * Next Generation Infrastructure Core- Run to Complete (ngic_rtc)
 * Data Plane function prototypes
 */
#include <rte_port.h>
#include <rte_hash_crc.h>

#include "interface.h"
#include "dp_stats.h"

extern uint64_t num_dns_processed;

/**
 * RTE Log type.
 */
#define RTE_LOGTYPE_EPC     RTE_LOGTYPE_USER1

/**
 * Number of ports.
 */
#define NUM_SPGW_PORTS      2

/**
 * Pipeline name size.
 */
#define PIPE_NAME_SIZE      80

/**
 * S1U port id.
 */
#define S1U_PORT_ID   0

/**
 * SGI port id.
 */

#define SGI_PORT_ID   1

/**
 * Default Queue id for S1U, WEST, SGI, EAST ports
 */
#define DEFAULT_QID   0

#define DL_RINGS_THRESHOLD 32

/* Per worker macros for DDN */
/* Macro to specify size of DDN notify_ring */
#define NOTIFY_RING_SIZE 2048
/* Macro to specify size of DDN notify_ring */
#define DL_RING_CONTAINER_SIZE (2048 * 2)
#define DL_PKT_POOL_SIZE (1024 * 32)
#define DL_PKT_POOL_CACHE_SIZE 32
#define DL_PKTS_RING_SIZE 1024

/* Borrowed from dpdk ip_frag_internal.c */
#define PRIME_VALUE	0xeaad8405

/** UL Bearer Map key for hash lookup.*/
struct ul_bm_key {
	/** s1u teid */
	uint32_t s1u_sgw_teid;
	/** rule id*/
	uint32_t rid;
};

/** DL Bearer Map key for hash lookup */
struct dl_bm_key {
	/** Ue ip */
	uint32_t ue_ipv4;
	/** Rule id */
	uint32_t rid;
};

/** Meta data used for directing packets to cores */
struct epc_meta_data {
	/** Pkt redirector flow ID */
	uint32_t flow_id;
	/** flag for DNS pkt */
	uint32_t dns;
	/** eNB IP from GTP-U */
	uint32_t enb_ipv4;
	/** Teid from GTP-U */
	uint32_t teid;
	/** DL Bearer Map key */
	struct dl_bm_key key;
};

/*
 * ASR- Note:
 * DP_MAX_CORES enables multiple cores per port. Mapping 1xDP_LCORE<>1xPORT_QUEUE
 * Temporary define: Optimize w/ ngic_rtcdrct evolution
 */

#define DP_MAX_LCORE RTE_LIBRTE_I40E_QUEUE_NUM_PER_PF

enum pkt_types {
	GTPU_ECHO_REQ = 0x01,
	GTPU_PKT = 0x02,
	DL_PKT = 0x08,
	KNI_PKT = 0x09,
	JUMBO_PKT = 0x0F,
	GTPU_UNSUPPORTED = 0x1F,
	BAD_PKT = 0xFE,
	UNKNOWN_PKT = 0xFF
};

/** UL ngic_rtc parameters - Per input port */
/**
 * Packet Types
 */
enum pkt_types s1u_pktyp;

struct epc_ul_params {
	/** Number of dns packets cloned by this worker */
	uint64_t num_dns_packets;
	/** Holds a set of rings to be used for downlink data buffering */
	struct rte_ring *dl_ring_container;
	/** Number of DL rings currently created */
	uint32_t num_dl_rings;
	/** For notification of modify_session so that buffered packets
	 * can be dequeued*/
	struct rte_ring *notify_ring;
	/** Pool for notification msg pkts */
	struct rte_mempool *notify_msg_pool;
	/** Holds number of packets received by uplink */
	uint64_t pkts_in;
	/** Holds number of packets sent out after uplink processing */
	uint64_t pkts_out;
	/* VCCCCB-34 Statistics - add current number of active sessions and RXbytes,
	 * TXbytes */
	/** Holds total number of ul bytes received at uplink */
	uint64_t tot_ul_bytes;
	/** Holds number of echo packets received by uplink */
	uint32_t pkts_echo;
	/** UL Runtime mbuf usage */
	struct ul_mbuf_stats ul_mbuf_rtime;
	/** Current s1u_pkt_handler() 'n' */
	uint64_t nb_pkts;
	/** Current s1u_pkt_handler()::gtpu_decap::ref pkts[i]->data_len */
	uint32_t ref_len;
	/** Current s1u_pkt_handler()::gtpu_decap::bad pkt_idx = pkts[i] */
	uint32_t bad_pkt_idx;
	/** Current s1u_pkt_handler()::gtpu_decap::bad pkts[i]->data_len */
	uint32_t bad_data_len;
	/** Current s1u_pkt_handler()::gtpu_decap::bad pkts[i]->pkt_len */
	uint32_t bad_pkt_len;
} __rte_cache_aligned;
typedef int (*ul_handler) (struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask);

/** DL ngic_rtc parameters - Per input port */
enum pkt_types sgi_pktyp;

struct epc_dl_params {
	/** Number of dns packets cloned by this worker */
	uint64_t num_dns_packets;
	/** Holds a set of rings to be used for downlink data buffering */
	struct rte_ring *dl_ring_container;
	/** Number of DL rings currently created */
	uint32_t num_dl_rings;
	/** For notification of modify_session so that buffered packets
	 * can be dequeued*/
	struct rte_ring *notify_ring;
	/** Pool for notification msg pkts */
	struct rte_mempool *notify_msg_pool;
	/** Holds number of packets received by downlink */
	uint64_t pkts_in;
	/** Holds number of packets sent out after downlink processing */
	uint64_t pkts_out;
	/* VCCCCB-34 Statistics - add current number of active sessions and RXbytes,
	 * TXbytes */
	/** Holds total number of dl bytes received at downlink */
	uint64_t tot_dl_bytes;
	/** DL Runtime mbuf usage */
	struct dl_mbuf_stats dl_mbuf_rtime;
	/** Current sgi_pkt_handler() 'n' */
	uint64_t nb_pkts;
	/** Current sgi_pkt_handler()::gtpu_encap::ref pkts[i]->data_len */
	uint32_t ref_len;
	/** Current sgi_pkt_handler()::gtpu_encap::bad pkt_idx = pkts[i] */
	uint32_t bad_pkt_idx;
	/** Current sgi_pkt_handler()::gtpu_encap::bad pkts[i]->data_len */
	uint32_t bad_data_len;
	/** Current sgi_pkt_handler()::gtpu_encap::bad pkts[i]->pkt_len */
	uint32_t bad_pkt_len;
	/** Holds number of packets queued for until DDN ACK not received */
	uint32_t ddn;
} __rte_cache_aligned;
typedef int (*dl_handler) (struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask);

/* ngic-rtc Packet Processing::Input-Outport[ports, queues] */
typedef struct port_pairs {
	int in_pid;               /* input port id */
	int in_qid;               /* input queue id */
	int out_pid;              /* output port id */
	int out_qid;              /* output queuq id */
} port_pairs_t;

/**
 * ngic_rtc function pointer
 *
 * @param func
 *  Function to run
 * @param arg
 *  Argument to ngic_rtc function
 * @param core
 *  Core to run ngic-rtc function on
 * @param ip_op
 *  Input-Outport[ports, queues] for function called
 */
typedef void ngic_rtc_func_t(void *param, port_pairs_t ip_op);

struct ngic_rtc_launch {
	ngic_rtc_func_t *func;    /* ngic_rtc function called */
	void *arg;                /* ngic_rtc function argument */
	/* Input-Outport[ports, queues] for function called */
	port_pairs_t ip_op_ports;
};

struct epc_lcore_config {
	int allocated;           /* #of ngic_rtc enabled */
	struct ngic_rtc_launch launch;
};

struct epc_app_params {
	/* CPU cores */
	struct epc_lcore_config lcores[DP_MAX_LCORE];
	int core_mct;           /* ASR- Note:: core_mct == core_stats */
	int core_iface;
	int core_spns_dns;
	int core_ul[NUM_SPGW_PORTS];
	int core_dl[NUM_SPGW_PORTS];

	/* Ports */
	uint32_t ports[NUM_SPGW_PORTS];

	/* Rx rings */
	struct rte_ring *epc_mct_spns_dns_rx;

	/* ngic_rtc packet processing core params */
	struct epc_ul_params ul_params[NUM_SPGW_PORTS];
	struct epc_dl_params dl_params[NUM_SPGW_PORTS];
} __rte_cache_aligned;
extern struct epc_app_params epc_app;

/**
 * Adds ngic_rtc function to cores, ports and queue to run
 *
 * @param func
 *  Function to run
 * @param arg
 *  Argument to ngic_rtc function
 * @param core
 *  Core to run ngic-rtc function on
 * @param ip_op
 *  Input-Outport[ports, queues] for function called
 */
void epc_alloc_lcore(ngic_rtc_func_t func, void *arg,
		int core, port_pairs_t ip_op);

/**
 * Initializes mngt handle function
 */
void mngtplane_init(void);

#ifdef HYPERSCAN_DPI
/**
 * Initializes DNS processing resources
 *
 */
void epc_spns_dns_init(void);
#endif

/**
 * Initialize EPC packet framework
 *
 * @param s1u_port_id
 *	Port id for s1u interface assigned by rte
 * @param sgi_port_id
 *	Port id for sgi interface assigned by rte
 */
void init_ngic_rtc_framework(uint8_t east_port_id, uint8_t west_port_id);

/**
 * Launches ingic_rtc data plane cores on callback funcs
 */
void launch_ngic_rtc_framework(void);

/**
 * UL ngic_rtc function
 *
 * @param arg
 *  Argument to ngic_rtc function
 * @param ip_op
 *  Input-Outport[ports, queues] for function called
 */
void epc_ul(void *args, port_pairs_t ip_op);

/**
 * DL ngic_rtc function
 *
 * @param arg
 *  Argument to ngic_rtc function
 * @param ip_op
 *  Input-Outport[ports, queues] for function called
 */
void epc_dl(void *args, port_pairs_t ip_op);

/**
 * Registers UL/DL function called by ngic_rtc launch
 *
 * @param f
 *	Function handler for packet processing
 * @param port
 *	Port to register the worker function for
 */
void register_ul_worker(ul_handler f, int port);
void register_dl_worker(dl_handler f, int port);

#endif /* __EPC_PACKET_FRAMEWORK_H__ */
