# Quick Guide for SGX CDR System Setup

````

CP ---> SGX Dealer-In ----> CDR Store -----> SGX Dealer-Out ----> FTP/SSL

````


A. To setup dealer-in and dealer-out

Go inside cloned path cd $(installation path)/sgxcdr/dealer/ and run the following command (as root / sudo):

````
./install.sh
````

After the above command is executed, all the dependent libraries will be downloaded and built.

Set the desired configuration in the config file in conf/dealer.json.
Update the "kmsserver", "kmsport" accordingly.
dealer->"runmode" as “IN”.
"cdrport" (use by default:6789) and "port" refers to the dealer-in port (use by default: 443)


Set the desired Public verification X.509 certificate and CA X.509 Certificate (optional) inside Enclave/ca_bundle.h

B. Build the dealer-in using the command:

````
make SGX_MODE=HW SGX_DEBUG=1
````

C. Run this command to find out dealer's MRENCLAVE and MRSIGNER. This binary is the dealer-in (you can optionally rename the binary or the folder to dealer-in)

````
./dealer -j conf/dealer.json -x
````

Also, update the #define KMS_MRSIGNER as dealer-in’s MRSIGNER in Enclave/ca_bundle.h

We need to come out of the dealer directory and make another directory called "dealer-out"
and copy all the contents of dealer.

````
#cd ..
#mkdir dealer-out
#cp -R dealer dealer-out
````

D. Go to dealer-out directory. Set the configuration in conf/dealer.json.
Update the "kmsserver", "kmsport" accordingly.
dealer->"runmode" as “OUT”.
"cdrport" (use by default:6790) and "port" refers to the dealer-out port (use by default: 445)

````
# cd dealer-out
````

E. Run this command again to check for the MRENCALVE and MRSIGNER for dealer-out. It should be same as dealer-in

````
# ./dealer -j conf/dealer.json -x
````

F. KMS Set up
Go to clone path sgxcdr/kms

Set the MRENCLAVE and MRSIGNER of dealer-in (or dealer-out) in Enclave/ca_bundle.h file.
Here, the structure array “const EnclaveMeasurements dealerMeasurements[]” should consist of MRENCLAVE and MRSIGNER similar to the following:

````

{
        "9525fc227fde387fxxxxxx...xxxx
        "63ef969cbc34ee46xxxxxx...xxxx
        0,
        0
},
{
        "",
        "",
        0,
        0
},
````

Set the desired configuration in conf/kms.json (MRENCLAVE and MRSIGNER)

G. Install the dependencies by running:

````
./install.sh
````

H. Build the kms using the command

````
# make SGX_MODE=HW SGX_DEBUG=1
````

J. ControlPlane node set up to use SGX CDR system

On the CP node, we have to set the IP, PORT, MRENCLAVE and MRSIGNER of dealer-in in the "interface.cfg" file at location ngic-rtc/config/interface.cfg

Place X509 Certificate PEM file issued by CA and X509 Private key PEM file inside certs/ folder.

Build the CP application with SGX_BUILD option enabled in CP install.sh
Go to CP folder (ngic-rtc/cp) and run the following:

````
make clean; make
````

KMS:

````
# ./kms -j conf/kms.json
````

Dealer In:

````
# ./dealer -j conf/dealer.json
````

Dealer Out: Here Go to the dealer-out folder and then execute this command.

````
# ./dealer -j conf/dealer.json
````

CP: Go to ngic-rtc/cp directory.

````
# ./run.sh
````

a. Only one instance of KMS is supported, however multiple KMS
   instances (with a cluster configuration) may be required for high
   availability

b. The signatures play a very important role in establishing secure connection between
   KMS and dealers. Any change in these signatures after connection establishment
   between KMS and dealers will prevent access to previously protected data.


SGX-CDR Issue summary and Resolution
-------------------------------------------------

````
FTP/SSL support in Dealer for CDR transfer      Fixed

Secure file listing support in Dealer out       Fixed

NGIC state info re-design for billing and LI    Fixed

CP state information re-design and integration testing  Fixed

DP state information re-design and integration testing  Fixed

Propagation of Charge information from DP to CP Fixed

Charging integration on CP + Secure CDR transfer interface      Fixed

SGX Server Stack Bringup        Fixed

CDR file size in SGX is not configurable        Fixed

Strange characters in CDR filenames when NODEID is different then number Fixed

Unable to delete CDR files through simple ftp client    Fixed

CDR files overwriten    Fixed

````
