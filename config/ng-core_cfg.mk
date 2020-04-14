#ZMQ_COMM::DEFAULT:: CP <COMM::ZMQ_PUSH_PULL> DP

#SET:SDN_ODL_BUILD:: CP <COMM::ODL | ZMQ/UDP> DP
#CAUTION::SDN_ODL_BUILD NOT TESTED
#CFLAGS += -DSDN_ODL_BUILD

# Path LIBGTPV2C library for CP & DP
LIBGTPV2C_ROOT = $(NG_CORE)/libgtpv2c

# SGX_BUILD service configured @install.sh
ifeq ($(SGX_BUILD), 1)
CFLAGS += -DSGX_BUILD
CFLAGS += -I$(NG_CORE)/linux-sgx/common/inc
LDFLAGS += -lssl -lcrypto
endif

