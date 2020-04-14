Copyright (c) 2020 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Next Generation Infrastructure Core (NGIC) VNF
==============================================

1. Introduction
-------------------------------------------
Evolved Packet Core (EPC) is a critical node in the wireless infrastructure,
which provides the data services to the end users. The NGIC is a
virtualized application providing the same service as the standalone node.
The SAE-GW (S-GW and P-GW)is the user plane node for the EPC which deals with
converged voice and data services on Long Term Evolution (LTE) networks. This
NGIC VNF has implements the SAE-GW. This has been developed using data plane
development kit version 16.04 (DPDK) optimized for Intel Architecture.

```text
                                       EPC Core
                             +-------------------------+
                             | +---------+ +---------+ |
                      Control| |  MME    | |  PCRF   | |
                       Signal| |         | |         | |
         +----------+  +-------+         | |         | |
+--+     |          |  |     | +-----+---+ +---+-----+ |
|UE+-----+          |  |     |       |         |       |
+--+     |          |  |     |   +-----------------+   |
         |          +--+     |   |   |s11      |Gx |   |
+--+     |  eNodeB  +--+     |   | +-------------+ |   |
|UE+-----+  (Base   |  |     |   | |    CP       | |   |
+--+     |  Station)|  |     |   | +-------------+ |   |   +--------------+
         |          |  |     |s1u| +-------------+ |sgi|   | External     |
+--+     |          |  +---------+ |    DP       | +-------+ Network      |
|UE+-----+          |  User  |   | +-------------+ |   |   |              |
+--+     +----------+  Data  |   |    NGIC NFV     |   |   |              |
              ||             |   +-----------------+   |   +--------------+
              ||             +-------------------------+
              ||
              ++
```

#### About DPDK

In this document, NGIC will be explained in detail with its own building blocks.

This document assumes the reader possesses the knowledge of DPDK concepts.
For more details, read DPDK's
[Getting Started Guide](http://dpdk.org/doc/guides/linux_gsg/index.html),
[Programmers Guide](http://dpdk.org/doc/guides/prog_guide/index.html),
[Sample Applications Guide](http://dpdk.org/doc/guides/sample_app_ug/index.html).

2.  Scope
----------
NGIC can be run on variety of servers running as a standalone application or on a
virtual machine using SRIOV and OVS dpdk as a NFVi layer.

3.	Feature List
----------------
The NGIC VNF currently supports the following SAE-GW features:

* PCC (Policy Control and Charging) rules configuration.
* ADC (Application Detection and control) rules configuration.
* Packet Filters for Service Data Flow (SDF) configuration.
* Packet Selectors/Filters for ADC configuration.
* UE sessions with default Bearer support.
* SDF and APN based Qos Metering for MBR.
* Charging by volume and asynchronous notification.
* Support for Multiple APNs
* Support for per-APN timer and volume based thresholds for CDR generation
* Enable command line or display stats periodically.
* IPv4 support
* Multiport support
* Sponsored Domain Name support

4.	High Level Design
----------------------
The NGIC VNF application is divided into Control plane (CP) and Data plane (DP).
Please refer to Figure 1 for the basic blocks in the NGIC VNG.
CP is used to set the PCC rules, QoS profiles, and UE Session to DP via UDP or
ZMQ communication performed by the cp_dp_api library.
Currently ADC rules are static, and provided by the adc_rules.cfg file.

```text
        +----------------+
        |                |
+-----> |    Control     |
 S11    |    Plane       |
<-----+ |                |
        |                |
        +-------+--------+
                |
                |
                | IPC
                |
                v
        +-----------------+
        |                 |
        |                 |
+-----> |     Data        | +--->
 S1U    |     Plane       |  SGi
<-----+ |                 | <---+
        |                 |
        +-----------------+
		Figure1
```

When a user packet arrives in DP, it follows the flow as mentioned in Figure 2 and appropriately sent to the output port.

```text
          +-----------------------------------------------------------------------------------------------------+
          |                        NGIC Data Plane Flow Diagram.                                                |
          |                               +---------------------------------+           +-----------------+     |        Flow1
          |  +------+  +------+  +------+ |    UE session                   |  +------+ | SDF & ADC Filter|     |    <--------------+
          |  | CDR  |  | APN  |  | PCC  | | +--------------------------+    |  | PCC  | |                 |     |        Flow2
   Flow1  |  |Charg |  | Meter|  | Meter| | |Default            sdf1   |    |  |Gating| |    sdf1         |     |    <--------------+
<-------+ |  |ing   |  |      |  |      | | |Bearer             sdf3   |    |  |      | | <-----------+   |     |
   Flow2  |  |      |  |      |  | sdf1 | | +--------------------------+    |  | sdf1 | |    sdf2         |     |
<-------+ |  |per UE|  |per UE|  | sdf2 | |                                 |  | sdf2 | | <-----------+   |     |        Flow3
   Flow3  |  |per ADC  |      |  | sdf3 | |                                 |  | sdf3 | |                 |     |    <--------------+
<-------+ |  |per   |  |      |  | sdf4 | | +--------------------------+    |  | sdf4 | |                 |     |        Flow4
   Flow4  |  | bearer  |      |  |      | | |Dedicated          sdf2   |    |  |      | | <-----------+   |     |    <--------------+
<-------+ |  |      |  |      |  |      | | |Bearer             sdf4   |    |  |      | |    sdf3         |     |
          |  +------+  +------+  +------+ | +--------------------------+    |  |      | | <-----------+   |     |
          |                               |                                 |  +------+ |    sdf4         |     |
          |                               +---------------------------------+           +-----------------+     |
          |                                                                                                     |
          +-----------------------------------------------------------------------------------------------------+

				Figure2 - explanation of DP flow with 4 flows.
```

The control plane manages session establishment and management by polling the configured S11 interface. Alternatively,
the s11 interface may be bypassed to read/write packet capture (pcap) files, as the allocation of TEID and IP addresses
are deterministic. The Control Plane manages within its own data structures all required information to process the
management of its connections, therefore tests may be performed independent on the data plane. The high level design of
the control plane is displayed in figure 3.

The control plane is limited to the types of gtpv2c messages it supports. Further, error handling is not implemented as
specified by 3gpp 29.274, specifically the MME will receive no indication of error. Messages indicating error type *may*
be displayed to console output, depending on type of error. Messages currently supported by the control plane include:

```text
  GTP Echo Request (RX) / GTP Echo Reply (TX)
  Create Session Request (RX) / Create Session Reply (TX)
  Delete Session Request (RX) / Delete Session Reply (TX)
  Modify Bearer Request (RX) / Modify Bearer Reply (TX)
  Create Bearer Request (TX) / Create Bearer Reply (RX)
  Delete Bearer Request (TX) / Delete Bearer Reply (RX)
  Bearer Resource Command (RX - on the condition TAD operation type specifies addition or deletion of packet filter)
```

Furthermore, the control plane expects the contents of these messages to contain certain Information Elements (IE). These may
differ from all corner cases allowed by 3gpp 29.274, which will be ignored, and may drop messages if some IEs are not present.

```text
                  +-------------------------------------------------------------+
                  |                     NGIC Control Plane                      |
                  |   +------------------+                 +------------+       |
                  |   | Create Session   |_________________| IP         |       |
                  |   | Parser/Responder |                 | allocation |       |
                  |   +------------------+_______________  +------------+       |
                  |    |                                 \                      |
                  |    |  +------------------+            \___+-------------+   |
                  |    |  | Modify Bearer    |________________| UE/Session/ |   |
                  |    |  | Parser/Responder |                | Bearer data |   |
                  |    |  +------------------+      __________+-------------+   |
                  |    |   |  .                    /                        |   |
          +-----> |    |   |  .                   /          +------------+ |   |
         S11/pcap |    |   |  .                  /        ___| Packet     | |   |
          <-----+ |    |   |  +------------------+       /   | Filters    | |   |
                  |    |   |  | Create Bearer    |______/    +------------+ |   |
                  |    |   |  | Parser/Responder |                          |   |
                  |    |   |  +------------------+                          |   |
                  |    |   |   |  ...                                       |   |
                  |    |   |   |    +------------------+                    |   |
                  |    |   |   |    | Delete Session   |____________________|   |
                  |    |   |   |    | Parser/Responder |           |            |
                  |    |   |   |    +------------------+           |            |
                  |    |   |   |     |                             |            |
                  |    |   |   |     |                             |            |
                  |   +------------------+                   +-------------+    |
                  |   |    CP_DP_API     |                   | CDR SSL xfer|=======> SGX-DEALER-IN
                  |   +------------------+                   +-------------+    |
                  +-----------||------------------------------------------------+
                              ||
                              \/
                              DP

                  Figure3 - NGIC Control Plane
```

For low level details on the Control Plane see [CP_README.MD](docs/CP_README.MD)

5.	Build, install, configure and test
------------------------------------------

Please refer to [install_notes] (INSTALL.MD)

6.	Test Plan
------------------

*	Tested upto 1M flows (32K, 128K, 512K, 1M)
*	Tested with multicore and multithreaded configurations.
*	Tested with Spirent VLS and pktgen(dpdk based) for traffic generation
	Note: pktgen 3.0 requires additional changes to support gtpu's inner ip address setting. The patch is part of the package.
*	Following traffic profiles are tested,
		- Spirent VLS	- 10K UE's, 1000 TPS, 	1MPPS
		- pktgen		- 50K UE's, 10K TPS,	2MPPS

7. Known Issues and limitations
-----------------------------
-       The current tested ADC rules are not fully conformant to 3GPP release 12 ADC AVPs.
-       IPV4 fragmentation and option header not supported.
-       IPSec not supported.
-       Only ethernet v2 frame format is supported.
-       Logic issues found in prepare_acl_parameter() in dp/acl.c
-       ACL context's (struct rte_acl_ctx) trans_table parameter is not being checked
        for NULL by dpdk. trans_table may appear as NULL during handling of stray GTP
        packets by DP.
-       Updates to filter packets arriving at the S1U and SGI interfaces for
        processing by linux. ARP Packets OR
        packets w/ dest address = {[S1U_IP, SGI_IP]; MULTICAST ADDR; BROADCAST ADDR}
        are sent to Linux for processing. All other packets are sent to the UL or DL
        fast path cores for processing. These enhancements need to be tested for following,
                1- To be tested with targeted packets
                2- To be tested with S1U and SGI GW configuration
-       Addressed htonl byte order conversion issues, however the following items need to be addressed,
                1- Some inconsistencies continue to remain in these fields
                   @~/interface/interface.c::zmq_mbuf_process::CREATE_SESSION, MODIFY_SESSION,
                   DELETE_SESSION. These needs to be addressed over test scenarios/setups.
                2- Byte order changes to ~/cp/gtpv2c_messages/modify_bearer.c, delete_session.c need
                   to be thoroughly tested.
                3- This patch has NOT been tested for SGWC-SGWU, PGWC-PGWU, and dedicated bearer
                   configurations/test scenarios. Hence byte order changes to
                   ~/cp/gtpv2c_messages/create_bearer.c, create_s5s8_session.c,
                   delete_bearer.c, delete_s5s8_session.c have not been tested.
-		For running ngic-rtc without kni STATIC_ARP must be enabled in the Makefile.
		ether.c::construct_ether_hdr(...) needs linux (kni) support to ARP discover S1U, SGI peer MAC.

-		Without KNI option is only for performance profiling. There is no support for:
		    - SGW-PGW separaton not suported in wokni option
		    - DP_DDN


8. NGIC-RTC-TMOPL Issue List, Summary and Resolution
-----------------------------------------------------

Summary				Resolution

FTP/SSL support in Dealer for CDR transfer	Fixed

Secure file listing support in Dealer out 	Fixed

UE IP allocation problem	Fixed

TMOPL FMS Deployment readiness
	
NGIC state info re-design for billing and LI	Fixed

CP state information re-design and integration testing	Fixed

DP state information re-design and integration testing	Fixed

Propagation of Charge information from DP to CP	Fixed

Charging integration on CP + Secure CDR transfer interface	Fixed

SGX Server Stack Bringup	Fixed

Many PDN connections for the same IMSI	Fixed

No PGW s5/s8 FTEID ip validation	Fixed

Cause Source Flag incorrect in CreateSessionResponse when IPpool is depleted	Fixed

APN checking is case sensitive	Fixed

DP stops processing after +- 2000 packets	Fixed

CP stops processing after CSReq with IpType=IPv6 or IPv4v6.	Fixed

Statistics - add current number of active sessions and RXbytes,TXbytes	Fixed

4G to 3G delete session support	Fixed

Allow first and last ip from IPpool to be allocated for the UE	Fixed

No CSres when CSReq does not contain mandatory IE	Fixed

Presence of APN NI (Network Identifier) in exported CDR record	Fixed

Segmentation fault when  create session request with incorrect apn_label	Fixed

CP does not free IP address after successful delete session procedure	Fixed

Daily Operations topics - guideline for starting all NGIC, DEALERS, KMS in backgroud	

DP hangs after a few hours	Fixed

GTP Echo Response on KNI S1u interface	Fixed

CDR content verification	Fixed

ModifyBearerResponse sent during ReleaseAccessBearers Procedure	Fixed

VLAN support - S1u and SGI on the same port
	
CDR time limit causes DP Segmentation Fault	Fixed

GTPV2C_CAUSE_CONTEXT_NOT_FOUND not send after CP restart	Fixed

causeForRecClosing should be abnormalRelease in fail scenario	Fixed

Incorrect MSISDN field in CDR for some MSISDNs (4860200000x)	Fixed

Graceful CP shutdown - closing sessions and CDRs Fixed
	
CDR file size in SGX is not configurable	Fixed

Strange characters in CDR filenames when NODEID is different then number	Fixed

CDR decoding - servedPDPPDNAddress encoding is incorrect	Fixed

Unable to delete CDR files through simple ftp client	Fixed

CDR decoding - servingNodeType encoding is incorrect	Fixed

The same FTEID allocated for two subscribers	Fixed

GTPC Recovery Restart Counter support	

DP crash segmentation fault - rte_kni_tx_burst	Fixed

Prepend CP / DP log with timestamp	Fixed

CDR decoding - incorrect encoding of integers	Fixed

UL-DFF - small number of packets when speedtest app is open	Fixed

Strange packets in uplink.pcap and downlink.pcap	Fixed

Zombie session support	

Two Sessions for the same UE - segmentation fault on DP and on CP	

Stats enchancement - CDR stats	

Stats should be generated independently from CLI mode

CDR files overwriten 	Fixed

APN Aggregate Maximum Bit Rate - support in CP	Fixed

Static UE IP allocation	

Private APN support	

