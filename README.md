# About the Project
CICFlowMeter++ is an upgraded version of the CICFlowMeter network traffic flow generator. It can be used to generate bidirectional traffic flows where the first packet determines the forward (source to destination) and backward (destination to source) directions, allowing the statistical time-related features to be calculated separately in the forward and backward directions. Users may add new features and edit the timeout.

NOTE: TCP flows are usually terminated upon connection teardown (by FIN packet) while UDP flows are terminated by a flow timeout. The flow timeout value can be assigned arbitrarily by the individual scheme e.g., 600 seconds for both TCP and UDP.

To learn more about CICFlowMeter++, our contributions, and citations, please use the below published paper:

For citation of the original CICFlowMeter (formerly ISCXFlowMeter) you can find below published papers:

Arash Habibi Lashkari, Gerard Draper-Gil, Mohammad Saiful Islam Mamun and Ali A. Ghorbani, "Characterization of Tor Traffic Using Time Based Features", In the proceeding of the 3rd International Conference on Information System Security and Privacy, SCITEPRESS, Porto, Portugal, 2017

Gerard Drapper Gil, Arash Habibi Lashkari, Mohammad Mamun, Ali A. Ghorbani, "Characterization of Encrypted and VPN Traffic Using Time-Related Features", In Proceedings of the 2nd International Conference on Information Systems Security and Privacy(ICISSP 2016) , pages 407-414, Rome , Italy

# Prerequisites

Clone Repository
>git clone https://github.com/PatriotLab/IoTCICFlowMeter

Install libpcap-dev
>sudo apt-get install libpcap-dev

Install JDK 17
>sudo apt-get install openjdk-17-jdk

Grant Execution Privileges to gradlew
>chmod +x gradlew

### Install jnetpcap local repo

for linux, sudo is a prerequisite
```
//linux :at the pathtoproject/jnetpcap/linux/jnetpcap-1.4.r1425
//windows: at the pathtoproject/jnetpcap/win/jnetpcap-1.4.r1425
mvn install:install-file -Dfile=jnetpcap.jar -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar
```

## Run

### Command Line

Select False to use the PATRIOT Lab's new CICFlowMeter++ features or True to use the orginal ones
>./gradlew exeCMD --args='“PathToPCAP" "PathToCSVOutputDirectory” <true/false>'

### GUI
Use the checkbox in the Offline tab to use the original CICFlowMeter features or leave it blank to use the new CICFlowMeter++ ones
>./gradlew execute

### IntelliJ IDEA

Linux (IDE Terminal)
> ./gradlew execute

Windows (IDE Terminal)
> gradlew execute

### Eclipse

Run eclipse with sudo
```
1. Right click App.java -> Run As -> Run Configurations -> Arguments -> VM arguments:
-Djava.library.path="pathtoproject/jnetpcap/linux/jnetpcap-1.4.r1425"  -> Run

2. Right click App.java -> Run As -> Java Application

```

# Make package

### IntelliJ IDEA
open a Terminal in the IDE
```
//linux:
$ ./gradlew distZip
//window
$ gradlew distZip
```
the zip file will be in the pathtoproject/CICFlowMeter/build/distributions

### Eclipse
At the project root
```
mvn package
```
the jar file will be in the pathtoproject/CICFlowMeter/target

--------------------------------------------------------------
#Extracted Features and Descriptions

Flow Duration
Duration of the flow in Microsecond

Total Fwd Packet
Total packets in the forward direction

Total Bwd packets
Total packets in the backward direction

Total Length of Fwd Packet	
Total size of packet in forward direction

Total Length of Bwd Packet
Total size of packet in backward direction

Fwd Packet Length Min, Max, Mean, Std, Variance
Minimum, Maximum, Mean, Standard Deviation, and Variance in the size of packet in forward direction

Bwd Packet Length Min, Max, Mean, Std, Variance
Minimum, Maximum, Mean, Standard Deviation, and Variance of packet in backward direction

Flow Bytes/s
Number of flow bytes per second

Flow Packets/s
Number of flow packets per second

Flow IAT Min, Max, Mean, Std, Variance
Minimum, Maximum, Mean, Standard Deviation, and Variance in the	time between two packets sent in the flow

Fwd IAT Min, Max, Mean, Std, Variance
Minimum, Maximum, Mean, Standard Deviation, and Variance in the time between two packets sent in the forward direction

Fwd IAT Total
Total time between two packets sent in the forward direction

Bwd IAT Min, Max, Mean, Std, Variance, Total
Minimum, Maximum, Mean, Standard Deviation, Variance, and Total time between two packets sent in the backward direction

Fwd PSH flags
Number of times the PSH flag was set in packets travelling in the forward direction (0 for UDP)

Bwd PSH Flags
Number of times the PSH flag was set in packets travelling in the backward direction (0 for UDP)

Fwd URG Flags
Number of times the URG flag was set in packets travelling in the forward direction (0 for UDP)

Bwd URG Flags
Number of times the URG flag was set in packets travelling in the backward direction (0 for UDP)

Fwd Header Length
Total bytes used for headers in the forward direction

Bwd Header Length
Total bytes used for headers in the backward direction

FWD Packets/s
Number of forward packets per second

Bwd Packets/s
Number of backward packets per second

Packet Length Min, Max, Mean, Std, Variance
Minimum, Maximum, Mean, Standard Deviation, and Variance in the length of a packet

FIN Flag Count -> Number of packets with FIN

SYN Flag Count -> Number of packets with SYN

RST Flag Count -> Number of packets with RST

PSH Flag Count -> Number of packets with PUSH

ACK Flag Count -> Number of packets with ACK

URG Flag Count -> Number of packets with URG

CWR Flag Count -> Number of packets with CWR

ECE Flag Count -> Number of packets with ECE

Down/Up Ratio
Download and upload ratio

Average Packet Size
Average size of packet

Fwd Segment Size Avg
Average size observed of the  in the forward direction

Bwd Segment Size Avg
Average size observed in the backward direction

Fwd Bytes/Bulk Avg
Average number of bytes bulk rate in the forward direction

Fwd Packet/Bulk Avg
Average number of packets bulk rate in the forward direction

Fwd Bulk Rate Avg
Average number of bulk rate in the forward direction

Bwd Bytes/Bulk Avg
Average number of bytes bulk rate in the backward direction

Bwd Packet/Bulk Avg
Average number of packets bulk rate in the backward direction

Bwd Bulk Rate Avg
Average number of bulk rate in the backward direction

Subflow Fwd Packets
The average number of packets in a sub flow in the forward direction
Subflow Fwd Bytes
The average number of bytes in a sub flow in the forward direction

Subflow Bwd Packets
The average number of packets in a sub flow in the backward direction

Subflow Bwd Bytes
The average number of bytes in a sub flow in the backward direction

Fwd Init Win bytes
The total number of bytes sent in initial window in the forward direction

Bwd Init Win bytes
The total number of bytes sent in initial window in the backward direction

Fwd Act Data Pkts
Count of packets with at least 1 byte of TCP data payload in the forward direction

Fwd Seg Size Min
Minimum segment size observed in the forward direction

Active Min, Max, Mean, Std, Variance 
Minimum, Maximum, Mean, Standard Deviation, and Variance
in the time a flow was active before becoming idle

Idle Min, Max, Mean, Std, Variance 
Minimum, Maximum, Mean, Standard Deviation, and Variance in the time a flow was idle before becoming active
--------------------------------------------------------------------------------------
