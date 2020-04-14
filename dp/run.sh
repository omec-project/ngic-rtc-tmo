#! /bin/bash
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

#LOG_LEVEL details
#	#define NOTICE 0
#	#define INFO 1
#	#define DEBUG 2
########################################################################
#LOG_LEVEL		dp/Makefile					Enabled Log level's
########################################################################
#	0			-DPERFORMANCE uncommented		ERR
#	0			-DPERFORMANCE commented			ERR, NOTICE
#	1			-DPERFORMANCE commented			ERR, NOTICE, INFO
#	2			-DPERFORMANCE commented			ERR, NOTICE, INFO, DEBUG

#Set the Log Level
LOG_LEVEL=0

#Checking dp system configuration's
source chk_dpcfg.sh
source $NG_CORE/config/dp_config.cfg

SIMU_CP_FLAG="CFLAGS += -DSIMU_CP"
ZMQ_COMM_FLAG="CFLAGS += -DZMQ_COMM"
DP_PATH="$NG_CORE/dp"
DPDK_PATH="$NG_CORE/dpdk"
DPDK_KMOD="igb_uio"
APP_PATH="./build"
APP="ngic_dataplane"
KNI_PORTMASK=03

# Check DP build configuration
# #############################################
if [ -z "$NG_CORE" ]; then
	echo "Please source $NG_CORE/setenv"
	echo -e "Check:: NG_CORE= $NG_CORE\tNULL!!!\n"
	exit
fi

SIMU_CP_CHK=`grep -e "^$SIMU_CP_FLAG" Makefile`
echo "SIMU_CP_CHK= $SIMU_CP_CHK..."
if [[ -n "$SIMU_CP_CHK" ]]; then
	echo "SIMU_CP Enabled in DP::Built-in session injection..."
	echo -e "Stopping ZMQ Streamer $NG_CORE/dev_scripts/stop-ZMQ_Streamer.sh script..."
	$NG_CORE/dev_scripts/stop-ZMQ_Streamer.sh
	echo -e "Running $NG_CORE/simu_gen.sh script..."
	$NG_CORE/simu_gen.sh
	echo "DP build configuration OK..."
else
	echo "SIMU_CP Disabled in DP::Live session injection..."
	echo -e "Starting ZMQ Streamer $NG_CORE/dev_scripts/start-ZMQ_Streamer.sh script..."
	$NG_CORE/dev_scripts/start-ZMQ_Streamer.sh
	echo "DP build configuration OK..."
fi

if [ -z $GTPU_SEQNB_IN ]; then GTPU_SEQNB_IN=0; fi
if [ -z $GTPU_SEQNB_OUT ]; then GTPU_SEQNB_OUT=0; fi

if [ "${SPGW_CFG}" == "01" ]; then
	ARGS="-l $CORELIST -n 4 --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY	\
				--file-prefix dp	\
				-w $S1U_PORT -w $S5S8_SGWU_PORT --	\
				--s1u_ip $S1U_IP	\
				--s1u_mac $S1U_MAC	\
				--s5s8_sgwu_ip $S5S8_SGWU_IP	\
				--s5s8_sgwu_mac $S5S8_SGWU_MAC	\
				--sgw_s5s8gw_ip $SGW_S5S8GW_IP	\
				--sgw_s5s8gw_mask $SGW_S5S8GW_MASK	\
				--log $LOG_LEVEL	\
				--numa $NUMA	\
				--gtpu_seqnb_in $GTPU_SEQNB_IN	\
				--gtpu_seqnb_out $GTPU_SEQNB_OUT \
				--spgw_cfg $SPGW_CFG	\
				--ul_iface $UL_IFACE	\
				--dl_iface $DL_IFACE	\
				--kni_portmask $KNI_PORTMASK"
elif [ "${SPGW_CFG}" == "02" ]; then
	ARGS="-l $CORELIST -n 4 --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY 	\
				--file-prefix dp	\
				-w $S5S8_PGWU_PORT -w $SGI_PORT	--	\
				--s5s8_pgwu_ip $S5S8_PGWU_IP	\
				--s5s8_pgwu_mac $S5S8_PGWU_MAC	\
				--sgi_ip $SGI_IP	\
				--sgi_mac $SGI_MAC	\
				--log $LOG_LEVEL	\
				--numa $NUMA	\
				--gtpu_seqnb_in $GTPU_SEQNB_IN	\
				--gtpu_seqnb_out $GTPU_SEQNB_OUT \
				--spgw_cfg $SPGW_CFG	\
				--ul_iface $UL_IFACE	\
				--dl_iface $DL_IFACE	\
				--kni_portmask $KNI_PORTMASK"
elif [ "${SPGW_CFG}" == "03" ]; then
	ARGS="-l $CORELIST -n 4 --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY 	\
				--file-prefix dp	\
				-w $S1U_PORT -w $SGI_PORT --	\
				--s1u_ip $S1U_IP	\
				--s1u_mask $S1U_MASK \
				--s1u_mac $S1U_MAC	\
				--sgi_ip $SGI_IP	\
				--sgi_mask $SGI_MASK \
				--sgi_mac $SGI_MAC	\
				--log $LOG_LEVEL	\
				--numa $NUMA	\
				--gtpu_seqnb_in $GTPU_SEQNB_IN	\
				--gtpu_seqnb_out $GTPU_SEQNB_OUT \
				--spgw_cfg $SPGW_CFG	\
				--ul_iface $UL_IFACE	\
				--dl_iface $DL_IFACE	\
				--kni_portmask $KNI_PORTMASK"
fi


if [ -n "${S1U_GW_IP}" ]; then
	ARGS="$ARGS --s1u_gw_ip $S1U_GW_IP"
fi

if [ -n "${SGI_GW_IP}" ]; then
	ARGS="$ARGS --sgi_gw_ip $SGI_GW_IP"
fi

echo $ARGS | sed -e $'s/--/\\\n\\t--/g'

USAGE="\nUsage:\trun.sh [ log | debug | dbg-dpdk | optm-dpdk]
	\tlog:	executes $APP w/ log enabled to date named file @
		\t\t$APP_PATH/logs.
		\t\tRequires Control-C exit even if $APP exits
	\tdebug:	executes $APP under gdb
	\tdbg-dpdk:		build DPDK w/ EXTRA_CLAGS==O0 for debug
	\toptm-dpdk:	build DPDK w/ O3 i.e. w/o debug\n"

if [ -z "$1" ]; then
	$APP_PATH/$APP $ARGS

elif [ "$1" == "log" ]; then
	if [ "$#" -eq "2" ]; then
		FILE="${FILE/.log/.$2.log}"
		echo "logging as $FILE"
	fi
	trap "killall $APP; exit" SIGINT
	stdbuf -oL -eL $APP_PATH/$APP $ARGS </dev/null &>$FILE & tail -f $FILE
	#valgrind --tool=memcheck --leak-check=full --log-file="sgwu_dp1.logs" $APP_PATH/$APP $ARGS

elif [ "$1" == "debug" ]; then
	GDB_EX="-ex 'set print pretty on' "
	echo $GDB_EX
	gdb $GDB_EX --args $APP_PATH/$APP $ARGS
	#valgrind --tool=memcheck --leak-check=full --log-file="sgwu_dp1.logs" $APP_PATH/$APP $ARGS

elif [ "$1" == "dbg-dpdk" ]; then
	export EXTRA_CFLAGS='-O0 -g'
	echo -e "set dpdk debug EXTRA_CFLAGS:\t$EXTRA_CFLAGS"
	# ASR- Section to copy over any specific dpdk dbg files
	read -p "Copy debug files  -> dp/, dpdk/; OK? y/n: " Answer
	if [[ "${Answer}" = "y" || "${Answer}" = "Y" ]]
	then
		echo "Insert script to copy/overlay required DP/DPDK files..."
	fi
	echo -e "\n\nBuilding dpdk..."
	echo -e "DPDK_TARGET=\t$RTE_TARGET"
	echo "DPDK_PATH= $RTE_SDK"
	pushd $RTE_SDK
	make -j install T=$RTE_TARGET
	DPDK_KMOD_CHK=$(lsmod | grep $DPDK_KMOD)
	if [ -n "$DPDK_KMOD_CHK" ]; then
		echo "Removing $DPDK_KMOD..."
		sudo rmmod $DPDK_KMOD
	fi
	echo "Inserting fresh $DPDK_KMOD..."
	sudo insmod "$RTE_TARGET"/kmod/igb_uio.ko
	$DPDK_PATH/usertools/dpdk-devbind.py -b igb_uio $S1U_PORT $SGI_PORT
	$DPDK_PATH/usertools/dpdk-devbind.py -s
	popd
	echo "Set DP build environment @NG_CORE_PATH= $NG_CORE"
	pushd $NG_CORE
	source $NG_CORE/setenv.sh
	popd
	echo -e "\n\nBuilding dp..."
	echo "DP_PATH= $DP_PATH"
	pushd $DP_PATH
	echo "Replace @:"
	echo -e "\t~/$DP_PATH/Makefile::"
	echo -e "\t\tCFLAGS += -O3 w/ CFLAGS += -g -O0"
	make clean; make
	popd
	echo -e "\ndp in dbg-dpdk mode  ready...Executing ./run.sh"
	echo "--------------------------------"
	echo $GDB_EX
	gdb $GDB_EX --args $APP_PATH/$APP $ARGS
	exit

elif [ "$1" == "optm-dpdk" ]; then
	unset EXTRA_CFLAGS
	echo -e "unset dpdk debug EXTRA_CFLAGS:\t$EXTRA_CFLAGS"
	# ASR- Section to replace any specific dpdk dbg w/ optimized files
	read -p "Copy Orig files  -> dp/, dpdk/; OK? y/n: " Answer
	if [[ "${Answer}" = "y" || "${Answer}" = "Y" ]]
	then
		echo "Insert script to copy/overlay required DP/DPDK files..."
	fi
	echo -e "\n\nBuilding dpdk..."
	echo -e "DPDK_TARGET=\t$RTE_TARGET"
	echo "DPDK_PATH= $RTE_SDK"
	pushd $RTE_SDK
	make -j install T=$RTE_TARGET
	DPDK_KMOD_CHK=$(lsmod | grep $DPDK_KMOD)
	if [ -n "$DPDK_KMOD_CHK" ]; then
		echo "Removing $DPDK_KMOD..."
		sudo rmmod $DPDK_KMOD
	fi
	echo "Inserting fresh $DPDK_KMOD..."
	sudo insmod "$RTE_TARGET"/kmod/igb_uio.ko
	$DPDK_PATH/usertools/dpdk-devbind.py -b igb_uio $S1U_PORT $SGI_PORT
	$DPDK_PATH/usertools/dpdk-devbind.py -s
	popd
	echo "Set DP build environment @NG_CORE_PATH= $NG_CORE"
	pushd $NG_CORE
	source $NG_CORE/setenv.sh
	popd
	echo -e "\n\nBuilding dp..."
	echo "DP_PATH= $DP_PATH"
	pushd $DP_PATH
	echo "Replace @:"
	echo -e "\t~/$DP_PATH/Makefile::"
	echo -e "\t\tCFLAGS += -g -O0 w/ CFLAGS += -O3"
	make clean; make
	popd
	echo -e "\nDP ready...Execute ./run.sh\n"
	echo -e "\ndp in optm-dpdk mode  ready...Executing ./run.sh"
	echo "--------------------------------"
	$APP_PATH/$APP $ARGS
	exit

else
	echo -e "$USAGE"
fi
