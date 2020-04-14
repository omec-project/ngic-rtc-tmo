#! /bin/bash

install_intel_sgx()
{
	#install Intel(R) SGX dependencies
	sudo apt-get update
	sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev build-essential

        #Uninstall Intel(R) SGX SDK
        if [ -d "/opt/intel/sgxsdk/" ]; then
                sudo /opt/intel/sgxsdk/uninstall.sh
        fi

        #Uninstall Intel(R) SGX Platform Software
        if [ -d "/opt/intel/sgxpsw/" ]; then
                sudo /opt/intel/sgxpsw/uninstall.sh
        fi

        #Uninstall Intel(R) SGX Driver
        if [ -d "/opt/intel/sgxdriver/" ]; then
                sudo /opt/intel/sgxdriver/uninstall.sh
        fi

        #install Intel(R) SGX Driver
        wget https://download.01.org/intel-sgx/linux-2.2/ubuntu64-server/sgx_linux_x64_driver_dc5858a.bin -P /tmp/sgxcdr
        chmod +x /tmp/sgxcdr/sgx_linux_x64_driver_dc5858a.bin
        sudo /tmp/sgxcdr/sgx_linux_x64_driver_dc5858a.bin

        #install Intel(R) SGX Platform Software
        wget https://download.01.org/intel-sgx/linux-2.2/ubuntu64-server/sgx_linux_x64_psw_2.2.100.45311.bin -P /tmp/sgxcdr
        chmod +x /tmp/sgxcdr/sgx_linux_x64_psw_2.2.100.45311.bin
        sudo /tmp/sgxcdr/sgx_linux_x64_psw_2.2.100.45311.bin

        #install Intel(R) SGX SDK
        wget https://download.01.org/intel-sgx/linux-2.2/ubuntu64-server/sgx_linux_x64_sdk_2.2.100.45311.bin -P /tmp/sgxcdr
        chmod +x  /tmp/sgxcdr/sgx_linux_x64_sdk_2.2.100.45311.bin
        sudo /tmp/sgxcdr/sgx_linux_x64_sdk_2.2.100.45311.bin

        source /opt/intel/sgxsdk/environment
}

	
build_kms_deps()
{
	sudo apt-get install cmake

        cd $BASEDIR/../modules
        git clone https://github.com/miloyip/rapidjson.git
        cd rapidjson
        git checkout af223d44f4e8d3772cb1ac0ce8bc2a132b51717f

	cd $DEALERDIR/deps

	#Clone MBEDTLS-2.15.1
	git clone https://github.com/ARMmbed/mbedtls.git -b mbedtls-2.15.1

	#Clone & build mbedtls-SGX
	git clone https://github.com/bl4ck5un/mbedtls-SGX.git
	cp mbedtls_sgx_ra_*.patch mbedtls-SGX/

	cd mbedtls-SGX
	git checkout 1529158

	rm -rf trusted/mbedtls-2.6.0/library
	rm -rf trusted/mbedtls-2.6.0/include
	cp -r ../mbedtls/library trusted/mbedtls-2.6.0/.
	cp -r ../mbedtls/include trusted/mbedtls-2.6.0/.
	rm -rf ../mbedtls

	patch -p0 < mbedtls_sgx_ra_prebuild.patch

	mkdir build
	cd build
	cmake ..
	make -j
	make install

	sleep 3

	cd ../
	patch -p0 < mbedtls_sgx_ra_postbuild.patch

	cp build/mbedtls_SGX-2.6.0/libs/libmbedtls_SGX_u.a build/mbedtls_SGX-2.6.0/lib/.
	
	#download rapidjson
	git submodule init
  	git submodule update
}

build_kms()
{
	cd $BASEDIR
	make clean
	make SGX_MODE=HW SGX_DEBUG=1
}

install_deps()
{
	install_intel_sgx
}

replace_dealer_mrenclave_mrsigner()
{
	cd $BASEDIR
	#replace MRENCLAVE value of Dealer in Enclave/ca_bundle.h file
	sed -i "0,/DEALER_MRENCLAVE/{s/DEALER_MRENCLAVE/${DEALER_MRENCLAVE}/}" Enclave/ca_bundle.h
	
	#replace MRSIGNER value of Dealer in Enclave/ca_bundle.h file
	sed -i "0,/DEALER_MRSIGNER/{s/DEALER_MRSIGNER/${DEALER_MRSIGNER}/}" Enclave/ca_bundle.h
}

BASEDIR=$PWD
DEALERDIR=$BASEDIR/../dealer

DEALER_MRENCLAVE=$1
DEALER_MRSIGNER=$2

install_deps
build_kms_deps
replace_dealer_mrenclave_mrsigner
build_kms

