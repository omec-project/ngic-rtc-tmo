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

# binary name
APP = ngic_controlplane

# all source are stored in SRCS-y

SRCS-y := main.c
SRCS-y += gtpv2c.c
SRCS-y += gtpv2c_set_ie.c
SRCS-y += debug_str.c
SRCS-y += ue.c
SRCS-y += cp_stats.c
SRCS-y += packet_filters.c
SRCS-y += sctf.c
SRCS-y += cp_commands.c
SRCS-y += cups_zmqresp.c

SRCS-y += gtpv2c_messages/bearer_resource_cmd.o
SRCS-y += gtpv2c_messages/create_bearer.o
SRCS-y += gtpv2c_messages/create_session.o
SRCS-y += gtpv2c_messages/create_s5s8_session.o
SRCS-y += gtpv2c_messages/delete_bearer.o
SRCS-y += gtpv2c_messages/delete_session.o
SRCS-y += gtpv2c_messages/delete_s5s8_session.o
SRCS-y += gtpv2c_messages/gtpv2c_echo.o
SRCS-y += gtpv2c_messages/modify_bearer.o
SRCS-y += gtpv2c_messages/downlink_data_notification.o
SRCS-y += gtpv2c_messages/release_access_bearer.o

SRCS-y += $(NG_CORE)/interface/ipc/common_ipc_api.o
SRCS-y += $(NG_CORE)/interface/interface.o

SRCS-y += $(NG_CORE)/cp_dp_api/cp_dp_api.o

CFLAGS += -Wno-psabi # suppress "The ABI for passing parameters with 64-byte alignment has changed in GCC 4.6"
CFLAGS += -Werror

CFLAGS += -I$(NG_CORE)/cp
CFLAGS += -I$(NG_CORE)/dp
CFLAGS += -I$(NG_CORE)/dp/pkt_engines
CFLAGS += -I$(NG_CORE)/cp_dp_api
CFLAGS += -I$(NG_CORE)/interface
CFLAGS += -I$(NG_CORE)/interface/ipc
CFLAGS += -I$(NG_CORE)/interface/udp
CFLAGS += -I$(NG_CORE)/interface/sdn
CFLAGS += -I$(NG_CORE)/interface/zmq
CFLAGS += -I$(NG_CORE)/interface/ssl
CFLAGS += -I$(LIBGTPV2C_ROOT)/include

# Mandatory CFLAGS, LDFLAGS- DO NOT MODIFY
# #############################################################
CFLAGS += -DCP_BUILD

# workaround for a gcc bug with noreturn attribute
#  http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_controlplane.o += -Wno-return-type
endif

LDLIBS += -L$(LIBGTPV2C_ROOT)/lib -lgtpv2c

LDLIBS += -lpcap

# ngic-cp application options CFLAGS
# #############################################################
#For SDN NB interface enable SDN_ODL_BUILD @ng-core_cfg.mk
#CAUTION::SDN_ODL_BUILD NOT TESTED
ifneq (,$(findstring SDN_ODL_BUILD, $(CFLAGS)))
	SRCS-y += nb.c
	LDLIBS += -ljson-c
	LDLIBS += -lcurl
#w/ SDN_ODL_BUILD::un-comment below line for req | resp timer stats
#CP<-->FPC<-->DP.
#CFLAGS += -DSYNC_STATS
ifneq (,$(findstring SYNC_STATS, $(CFLAGS)))
	SRCS-y += cups_sdnresp.c
endif
else
	SRCS-y += $(NG_CORE)/interface/zmq/zmq_push_pull.o
endif

#Integrate ssl_client if SGX_BUILD
ifneq (,$(findstring SGX_BUILD, $(CFLAGS)))
	SRCS-y += $(NG_CORE)/interface/ssl/ssl_client.c
endif

LDFLAGS += -L/usr/local/lib -lzmq

# ngic-cp debug/testing/profiling options CFLAGS
# #############################################################
#Enable'-g -O0' option for gdb
CFLAGS += -O3
#CFLAGS += -g -O0

#un-comment below line to remove all log level for operational preformance.
CFLAGS += -DPERFORMANCE

#Enable '-E' option to debug preprocessor output
#CFLAGS += -E

CFLAGS += $(WERROR_FLAGS)
CFLAGS_config.o := -D_GNU_SOURCE

# Un-comment below line to read fake cp config.
#CFLAGS += -DSIMU_CP

# Un-comment below line to send fake delete session request from simulator.
#CFLAGS += -DDEL_SESS_REQ

ifneq (,$(findstring SIMU_CP, $(CFLAGS)))
	SRCS-y += $(NG_CORE)/test/simu_cp/simu_cp.o
endif

# ngic-cp application security check CFLAGS
###############################################################
SECURITY_FLAGS = -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fexceptions  -fpie -fstack-protector-all -fstack-protector-strong -Wall -Werror=format-security -Werror=implicit-function-declaration

CFLAGS += $(SECURITY_FLAGS)

# ngic-cp include make overlays
# #############################################################
include $(RTE_SDK)/mk/rte.extapp.mk

