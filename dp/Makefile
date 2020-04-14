# Copyright (c) 2020 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

MAKEFLAGS += -j

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk
include $(NG_CORE)/config/ng-core_cfg.mk

#DIRS-y += pkt_engines
# binary name
APP = ngic_dataplane
# all source are stored in SRCS-y
SRCS-y := main.c\
	userplane_handler.c\
	config.c\
	init.c\
	dataplane.c\
	gtpu.c\
	ether.c\
	ipv4.c\
	util.c\
	acl.c\
	meter.c\
	adc_table.c\
	pcc_table.c\
	sess_table.c\
	dp_commands.c\
	dp_stats.c\
	timer_stats.c\
	timer_threshold.c\
	kni_handler.c\
	gtpu_echo.c\
	mngtplane_handler.c\
	pkt_engines/ngic_rtc_framework.o\
	$(NG_CORE)/interface/interface.o\
	$(NG_CORE)/cp_dp_api/cp_dp_api.o\
	$(NG_CORE)/interface/ipc/common_ipc_api.o

CFLAGS += -I$(SRCDIR)/
CFLAGS += -I$(NG_CORE)/cp
CFLAGS += -I$(SRCDIR)/pkt_engines
CFLAGS += -I$(NG_CORE)/cp_dp_api
CFLAGS += -I$(NG_CORE)/interface
CFLAGS += -I$(NG_CORE)/interface/ipc
CFLAGS += -I$(NG_CORE)/interface/udp
CFLAGS += -I$(NG_CORE)/interface/sdn
CFLAGS += -I$(NG_CORE)/interface/zmq
CFLAGS += -I$(NG_CORE)/interface/ssl
CFLAGS += -I$(NG_CORE)/lib/libsponsdn
CFLAGS += -I$(NG_CORE)/dpdk/lib/librte_acl/
CFLAGS += -I$(LIBGTPV2C_ROOT)/include
CFLAGS += -I$(NG_CORE)/test/unit_test/

# Mandatory CFLAGS, LDFLAGS- DO NOT MODIFY
# #############################################################
CFLAGS += -Wno-psabi # suppress "The ABI for passing parameters with 64-byte alignment has changed in GCC 4.6"

CFLAGS += -DLDB_DP	# should be included for dataplane.

CFLAGS += -DDP_BUILD

CFLAGS += -Werror
CFLAGS += -Wunused-variable

# un-comment below line to Expose declaration of tdestroy()#
CFLAGS_config.o := -D_GNU_SOURCE

# ngic-dp application security check CFLAGS
# #############################################################
SECURITY_FLAGS = -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fexceptions -fpie -fstack-protector-all -fstack-protector-strong -Wall -Werror=format-security -Werror=implicit-function-declaration -Wno-unused-function

CFLAGS += $(SECURITY_FLAGS)

# workaround for a gcc bug with noreturn attribute
#  http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_dataplane.o += -Wno-return-type
endif
LDFLAGS += -lm -lcrypto

LDFLAGS += -lrte_pmd_af_packet

LDFLAGS += -lpcap

# ngic-dp application options CFLAGS
# #############################################################
#For SDN NB interface enable SDN_ODL_BUILD @ng-core_cfg.mk
#CAUTION::SDN_ODL_BUILD NOT TESTED
ifneq (,$(findstring SDN_ODL_BUILD, $(CFLAGS)))
	SRCS-y += $(NG_CORE)/interface/zmq/zmqsub.o
	SRCS-y += $(NG_CORE)/interface/zmq/zmqpub.o
else
	SRCS-y += $(NG_CORE)/interface/zmq/zmq_push_pull.o
endif

LDFLAGS += -L/usr/local/lib -lzmq

#Integrate ssl_client if SGX_BUILD
ifneq (,$(findstring SGX_BUILD, $(CFLAGS)))
	SRCS-y += $(NG_CORE)/interface/ssl/ssl_client.c
endif

# CPU Architecture specific enhancements
# #############################################################
# Set DP_AVX_SUPPORT = 0; Disable AVX enhancements in DP
# Set DP_AVX_SUPPORT = 1; Enable AVX enhancements in DP
DP_AVX_SUPPORT = 0

# DO NOT MODIFY AVX_CONFIRMED
AVX_CONFIRMED = 0
ifeq ($(DP_AVX_SUPPORT),1)
ifneq ($(shell gcc -mavx512f -dM -E - < /dev/null | egrep "AVX512F"),)
ifneq ($(shell lscpu | egrep "avx512f"),)
	AVX_CONFIRMED = 1
endif # gcc -mavx512f
endif # lscpu avx512f
ifeq ($(AVX_CONFIRMED),1)
$(info "DP Build: w/ DP_AVX_SUPPORT")
    SRCS-y += pkt_engines/epc_ul_avx.o
    SRCS-y += pkt_engines/epc_dl_avx.o
    CFLAGS += -mavx512f
else
$(info "DP Build: w/o DP_AVX_SUPPORT")
    SRCS-y += pkt_engines/epc_ul.o
    SRCS-y += pkt_engines/epc_dl.o
endif # AVX_CONFIRMED
else
$(info "DP Build: disabled DP_AVX_SUPPORT")
    SRCS-y += pkt_engines/epc_ul.o
    SRCS-y += pkt_engines/epc_dl.o
endif # DP_AVX_SUPPORT

# ngic-dp debug/testing/profiling options CFLAGS
# #############################################################
# gdb: un-comment 'CFLAGS += -g -O0' comment 'CFLAGS += -O3'
CFLAGS += -O3
#CFLAGS += -g -O0

# Un-comment below line to add unit_test.
#CFLAGS += -DUNIT_TEST
#Unit Test Files
ifneq (,$(findstring UNIT_TEST, $(CFLAGS)))
	SRCS-y += $(NG_CORE)/test/unit_test/pkt_proc.c
endif

#un-comment below line to remove all log level for operational preformance.
CFLAGS += -DPERFORMANCE

#un-comment below line to generate pcap on east-west interfaces
#CFLAGS += -DPCAP_GEN

# Un-comment below line to read fake cp config.
#CFLAGS += -DSIMU_CP

# Un-comment below line to send fake delete session request from simulator.
#Note: This will impact data traffic performance.
#CFLAGS += -DDEL_SESS_REQ

# VS- Re-use CP struct cp_stats_t{} counters for built-in session simulator stats
ifneq (,$(findstring SIMU_CP, $(CFLAGS)))
	 SRCS-y += $(NG_CORE)/test/simu_cp/simu_cp.o\
	$(NG_CORE)/test/simu_cp/pkt_filtrs.o
endif

# Enable STATIC ARP for testing with il_nperf
# Un-comment below line to enable STATIC ARP
#CFLAGS += -DSTATIC_ARP

# Un-comment to enable Fragmentation and re-assemply
#CFLAGS += -DFRAG

# Un-comment to re-size MTU on SGI side
#CFLAGS += -DSGI_ETHER_MTU=1514

# Un-comment below line to print ADC, PCC, METER and SDF rule entry
# passed from FPC-SDN in add entry operation.
# Note : This flag works with Log level 'DEBUG'
#CFLAGS += -DPRINT_NEW_RULE_ENTRY

# Un-comment below line to enable GTP-ECHO packets count on display
#CFLAGS += -DEXSTATS

# Un-comment below line to enable AUTO-ANALYSIS mode for perforamance measurement
# Criteria to uncomment: if (PPS * test_duration) > 0.1M, then enable PERF_ANALYSIS flag
#Note: This option might impact data traffic performance.
#CFLAGS += -DPERF_ANALYSIS
ifneq (,$(findstring PERF_ANALYSIS, $(CFLAGS)))
# Enable TIMER_STATS for probing PERF_ANALYSIS
#	CFLAGS += -DTIMER_STATS
endif

# Un-comment below line if you have 16 x 1GB hugepages.
#CFLAGS += -DHUGE_PAGE_16GB

# ngic-dp inter-op/functional options CFLAGS
# #############################################################
# Un-comment below line to enable DDN(Downlink data notification)
#CAUTION::DP_DDN NOT TESTED
#CFLAGS += -DDP_DDN
ifneq (,$(findstring DP_DDN, $(CFLAGS)))
	SRCS-y += ddn.c
endif

# Un-comment below line to enable Rating group CDRs.
# Disable/Comment out  RATING_GRP_CDR for performance profiling.
#CFLAGS += -DRATING_GRP_CDR

# ASR- Un-comment below line to enable GTPU HEADER Sequence Number option.
#CFLAGS += -DGTPU_HDR_SEQNB

# Un-comment below line to enable hyperscan DPI.
# ASR- HYPERSCAN to be tested
#CFLAGS += -DHYPERSCAN_DPI
ifneq (,$(findstring HYPERSCAN_DPI, $(CFLAGS)))
	SRCS-y += pkt_engines/epc_spns_dns.o
	LDFLAGS += -L$(NG_CORE)/lib/libsponsdn/x86_64-native-linuxapp-gcc/lib/ -lsponsdn
	LDFLAGS += -L$(HYPERSCANDIR)/build/lib
	LDFLAGS += -lexpressionutil -lhs -lhs_runtime -lstdc++
endif

# Un-comment below line to enable PCC, ADC, CDR, FILTERING, METERING pkt_engines stages.
#CFLAGS += -DINCLUDE_MTR_STAGE

# ngic-dp  CFLAGS to be deprecated
# #############################################################
# Un-comment below line to configure DP Tables from DP app.
#CFLAGS += -DDP_TABLE_CONFIG

# Un-comment below line to enable SDF Metering
#CFLAGS += -DSDF_MTR

# Un-comment below line to enable APN Metering
#CFLAGS += -DAPN_MTR

# Un-comment below line to read acl rules from file.
#CFLAGS += -DACL_READ_CFG

# ngic-dp include make overlays
# #############################################################
include $(RTE_SDK)/mk/rte.extapp.mk
