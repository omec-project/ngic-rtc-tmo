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

#Checking cp system configuration's
source chk_cpcfg.sh

source $NG_CORE/config/dp_config.cfg
source $NG_CORE/config/cp_config.cfg

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$NG_CORE/libgtpv2c/lib

SIMU_CP_FLAG="CFLAGS += -DSIMU_CP"
ZMQ_COMM_FLAG="CFLAGS += -DZMQ_COMM"

APP_PATH="./build"
APP="ngic_controlplane"
LOG_LEVEL=1

# Check CP build configuration
# #############################################
if [ -z "$NG_CORE" ]; then
	echo "Please source $NG_CORE/setenv"
	echo -e "Check:: NG_CORE= $NG_CORE\tNULL!!!\n"
	exit
fi

SIMU_CP_CHK=`grep -e "^$SIMU_CP_FLAG" Makefile`
echo "SIMU_CP_CHK= $SIMU_CP_CHK..."
if [[ -n "$SIMU_CP_CHK" ]]; then
	echo "SIMU_CP Enabled in CP::Built-in session injection..."
	echo -e "Running $NG_CORE/simu_gen.sh script..."
	$NG_CORE/simu_gen.sh
else
	echo "SIMU_CP Disabled in CP::Live S1-MME session injection..."
fi
echo "CP build configuration OK..."

# Read CP operational config
################################################
echo -e "\nReading CP operational config..."
IFSTMP=$IFS
IFS=$', '
# Read APN LIST
read -a APNS <<< "${APN}"
for _apn in "${APNS[@]}"
do
   APN_LST="$APN_LST -a $_apn"
done
echo "APN ARGS- $APN_LST"

# Read IP_POOL LIST
read -a IP_POOLS  <<< "${IP_POOL}"
for _ip_pool in "${IP_POOLS[@]}"
do
   IP_POOL_LST="$IP_POOL_LST -i $_ip_pool"
done
echo "IP_POOL ARGS- $IP_POOL_LST"

# Read IP_MASK LIST
read -a IP_MASKS  <<< "${IP_POOL_MASK}"
for _ip_mask in "${IP_MASKS[@]}"
do
   IP_MASK_LST="$IP_MASK_LST -p $_ip_mask"
done
echo "IP_MASK ARGS- $IP_MASK_LST"

# Read PRIMARY DNS LIST
read -a PRIMARY_DNS_IPS  <<< "${PRIMARY_DNS_IP}"
for _primary_dns in "${PRIMARY_DNS_IPS[@]}"
do
   PRIMARY_DNS_LST="$PRIMARY_DNS_LST -e $_primary_dns"
done
echo "PRIMARY_DNS ARGS- $PRIMARY_DNS_LST"

# Read SECONDARY DNS LIST
read -a SECONDARY_DNS_IPS  <<< "${SECONDARY_DNS_IP}"
for _secondary_dns in "${SECONDARY_DNS_IPS[@]}"
do
   SECONDARY_DNS_LST="$SECONDARY_DNS_LST -f $_secondary_dns"
done
echo "SECONDARY_DNS ARGS- $SECONDARY_DNS_LST"

# Read TMR_TRSHLD LIST
read -a TMR_TRSHLDS  <<< "${TMR_TRSHLD}"
for _tmr_trshld in "${TMR_TRSHLDS[@]}"
do
   TMR_TRSHLD_LST="$TMR_TRSHLD_LST -m $_tmr_trshld"
done
echo "TMR_TRSHLD ARGS- $TMR_TRSHLD_LST"

# Read VOL_TRSHLD LIST
read -a VOL_TRSHLDS  <<< "${VOL_TRSHLD}"
for _vol_trshld in "${VOL_TRSHLDS[@]}"
do
   VOL_TRSHLD_LST="$VOL_TRSHLD_LST -o $_vol_trshld"
done
echo "VOL_TRSHLD ARGS- $VOL_TRSHLD_LST"

# Read UL_AMBR LIST
read -a UL_AMBRS  <<< "${UL_AMBR}"
for _ul_ambr in "${UL_AMBRS[@]}"
do
   UL_AMBR_LST="$UL_AMBR_LST -j $_ul_ambr"
done
echo "UL_AMBR ARGS- $UL_AMBR_LST"

# Read DL_AMBR LIST
read -a DL_AMBRS  <<< "${DL_AMBR}"
for _dl_ambr in "${DL_AMBRS[@]}"
do
   DL_AMBR_LST="$DL_AMBR_LST -k $_dl_ambr"
done
echo "DL_AMBR ARGS- $DL_AMBR_LST"

IFS=$IFSTMP

# Run CP w/ options defined
################################################
echo -e "\nRunning CP with options defined..."
USAGE=$"Usage: run.sh [ debug | log ]
	debug:	executes $APP under gdb
	log:	executes $APP with logging enabled to date named file under
		$APP_PATH/logs. Requires Control-C to exit even if $APP exits"

# Set CP ARGS
################################################
if [ "${SPGW_CFG}" == "01" ]; then
	ARGS="-l $CORELIST --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY --file-prefix cp --no-pci -- \
      -d $SPGW_CFG            \
	  -s $S11_SGW_IP          \
	  -w $S1U_SGW_IP          \
	  -r $S5S8_SGWC_IP        \
	  -g $S5S8_PGWC_IP        \
	  -v $S5S8_SGWU_IP        \
	  -u $S5S8_PGWU_IP        \
	  $APN_LST                \
	  $IP_POOL_LST            \
	  $IP_MASK_LST            \
	  $PRIMARY_DNS_LST        \
	  $SECONDARY_DNS_LST      \
	  $TMR_TRSHLD_LST         \
	  $VOL_TRSHLD_LST         \
	  $UL_AMBR_LST            \
	  $DL_AMBR_LST            \
	  -c $SEND_CDR            \
	  -n $NODE_ID             \
	  -l $LOG_LEVEL"
elif [ "${SPGW_CFG}" == "02" ]; then
	ARGS="-l $CORELIST --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY --file-prefix cp --no-pci -- \
      -d $SPGW_CFG            \
	  -s $S11_SGW_IP          \
	  -w $S1U_SGW_IP          \
	  -r $S5S8_SGWC_IP        \
	  -g $S5S8_PGWC_IP        \
	  -v $S5S8_SGWU_IP        \
	  -u $S5S8_PGWU_IP        \
	  $APN_LST                \
	  $IP_POOL_LST            \
	  $IP_MASK_LST            \
	  $PRIMARY_DNS_LST        \
	  $SECONDARY_DNS_LST      \
	  $TMR_TRSHLD_LST         \
	  $VOL_TRSHLD_LST         \
	  $UL_AMBR_LST            \
	  $DL_AMBR_LST            \
	  -c $SEND_CDR            \
	  -n $NODE_ID             \
	  -l $LOG_LEVEL"
elif [ "${SPGW_CFG}" == "03" ]; then
	ARGS="-l $CORELIST --socket-mem $NUMA0_MEMORY,$NUMA1_MEMORY --file-prefix cp --no-pci -- \
      -d $SPGW_CFG            \
	  -s $S11_SGW_IP          \
	  -w $S1U_SGW_IP          \
	  -g $S5S8_PGWC_IP        \
	  -u $S5S8_PGWU_IP        \
	  $APN_LST                \
	  $IP_POOL_LST            \
	  $IP_MASK_LST            \
	  $PRIMARY_DNS_LST        \
	  $SECONDARY_DNS_LST      \
	  $TMR_TRSHLD_LST         \
	  $VOL_TRSHLD_LST         \
	  $UL_AMBR_LST            \
	  $DL_AMBR_LST            \
	  -c $SEND_CDR            \
	  -n $NODE_ID             \
	  -l $LOG_LEVEL"
fi

echo $ARGS

echo -e "Configure S11_SGW_IFACE= $S11_SGW_IFACE= ...\n"
ifconfig $S11_SGW_IFACE $S11_SGW_IP netmask $S11_MASK
ifconfig $S11_SGW_IFACE

if [ -z "$1" ]; then
	$APP_PATH/$APP $ARGS

elif [ "$1" == "pcap" ]; then
    $APP_PATH/$APP $ARGS -x $NG_CORE/pcap/cp_in.pcap -y $NG_CORE/pcap/cp_out.pcap

elif [ "$1" == "log" ]; then

	if [ "$#" -eq "2" ]; then
		FILE="${FILE/.log/.$2.log}"
		echo "logging as $FILE"
	fi
	trap "killall $APP; exit" SIGINT
	stdbuf -oL -eL $APP_PATH/$APP $ARGS </dev/null &>$FILE & tail -f $FILE

elif [ "$1" == "debug" ];then

	GDB_EX="-ex 'set print pretty on'"
	gdb $GDB_EX --args $APP_PATH/$APP $ARGS

#elif [ "$1" == "zmq" ];then
#	pgrep -fa python | grep req_streamer_dev.py  &> /dev/null
#	if [ $? -eq 1 ]; then
#		echo "Starting req_streamer_dev.py"
#		$NG_CORE/test/zmq_device/req_streamer_dev.py &
#	else
#		echo "req_streamer_dev.py already Running"
#	fi

#	pgrep -fa python | grep resp_streamer_dev.py  &> /dev/null
#	if [ $? -eq 1 ]; then
#		echo "Starting resp_streamer_dev.py"
#		$NG_CORE/test/zmq_device/resp_streamer_dev.py &
#	else
#		echo "resp_streamer_dev.py already Running"
#	fi
#	sleep 2

	$APP_PATH/$APP $ARGS

#elif [ "$1" == "kill" ];then
#	pgrep -fa python | grep req_streamer_dev.py  &> /dev/null
#	if [ $? -eq 1 ]; then
#		echo "req_streamer_dev.py no longer running.."
#	else
#		echo "Stopping req_streamer_dev.py"
#		killall -9 req_streamer_dev.py
#	fi

#	pgrep -fa python | grep resp_streamer_dev.py  &> /dev/null
#	if [ $? -eq 1 ]; then
#		echo "resp_streamer_dev.py no longer running.."
#	else
#		echo "Stopping resp_streamer_dev.py"
#		killall -9 resp_streamer_dev.py
#	fi

else
	echo "$USAGE"
fi
