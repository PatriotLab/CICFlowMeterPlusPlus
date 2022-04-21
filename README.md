# About the Project
CICFlowMeter++ is an upgraded version of the CICFlowMeter network traffic flow generator. It can be used to generate bidirectional traffic flows where the first packet determines the forward (source to destination) and backward (destination to source) directions, allowing the statistical time-related features to be calculated separately in the forward and backward directions. Users may add new features and edit the timeout.

NOTE: TCP flows are usually terminated upon connection teardown (by FIN packet) while UDP flows are terminated by a flow timeout. The flow timeout value can be assigned arbitrarily by the individual scheme e.g., 600 seconds for both TCP and UDP.

To learn more about CICFlowMeter++, our contributions, and citations, please use the below published paper:

For citation of the original CICFlowMeter (formerly ISCXFlowMeter) you can find below published papers:

Arash Habibi Lashkari, Gerard Draper-Gil, Mohammad Saiful Islam Mamun and Ali A. Ghorbani, "Characterization of Tor Traffic Using Time Based Features", In the proceeding of the 3rd International Conference on Information System Security and Privacy, SCITEPRESS, Porto, Portugal, 2017

Gerard Drapper Gil, Arash Habibi Lashkari, Mohammad Mamun, Ali A. Ghorbani, "Characterization of Encrypted and VPN Traffic Using Time-Related Features", In Proceedings of the 2nd International Conference on Information Systems Security and Privacy(ICISSP 2016) , pages 407-414, Rome , Italy

# Prerequisites

Install libpcap-dev
>sudo apt-get install libpcap-dev

Install JDK 17
>sudo apt-get install openjdk-17-jdk


### Install jnetpcap local repo

for linux, sudo is a prerequisite
```
//linux :at the pathtoproject/jnetpcap/linux/jnetpcap-1.4.r1425
//windows: at the pathtoproject/jnetpcap/win/jnetpcap-1.4.r1425
mvn install:install-file -Dfile=jnetpcap.jar -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar
```

## Run

### Command Line

>./gradlew exeCMD --args={“PathToPCAP PathToCSVOutputDirectory”}

### GUI
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

Timestamp
Duration
Protocol
Packet Count
FwdPacketCount
BwdPacketCount


#### Packet Length Max, Min, Mean, Std, Total

Maximum, Minimum, Mean, Standard Deviation, and Total Packet size

#### Header Length Max, Min, Mean, Std, Total

Maximum, Minimum, Mean, Standard Deviation, and Total Packet Header size


#### Fwd Packet Length Max, Min, Mean, Std, Total

Maximum, Minimum, Mean, Standard Deviation, and Total Packet size in the forward direction


#### Fwd Header Length Max, Min, Mean, Std, Total

Maximum, Minimum, Mean, Standard Deviation, and Total Packet Header size in the forward direction


#### Bwd Packet Length Max, Min, Mean, Std, Total

Maximum, Minimum, Mean, Standard Deviation, and Total Packet Header size in the backward direction


#### Bwd Header Length Max, Min, Mean, Std, Total

Maximum, Minimum, Mean, Standard Deviation, and Total Packet Header size in the backward direction


#### Fwd, Bwd, Total Count FIN Flag

FIN Flags in the Forward and Backward directions and Total


#### Fwd, Bwd, Total Count PSH Flag

PSH Flags in the Forward and Backward directions and Total


#### Fwd, Bwd, Total Count URG Flag

URG Flags in the Forward and Backward directions and Total

#### Fwd, Bwd, Total Count ECE Flag

ECE Flags in the Forward and Backward directions and Total


#### Fwd, Bwd, Total Count SYN Flag

SYN Flags in the Forward and Backward directions and Total


#### Fwd, Bwd, Total Count ACK Flag

ACK Flags in the Forward and Backward directions and Total


#### Fwd, Bwd, Total Count CWR Flag

CWR Flags in the Forward and Backward directions and Total

#### Fwd, Bwd, Total Count RST Flag

RST Flags in the Forward and Backward directions and Total


#### IAT Max, Min, Mean, Std, Total

Maximum, Minimum, Mean, Standard Deviation, and Total time between packet arrivals


#### Fwd IAT Max, Min, Mean, Std, Total

Maximum, Minimum, Mean, Standard Deviation, and Total time between packet arrivals in the forward direction


#### Bwd IAT Max, Min, Mean, Std, Total

Maximum, Minimum, Mean, Standard Deviation, and Total time between packet arrivals in the backward direction


#### Active Max, Min, Mean, Std, Total

Maximum, Minimum, Mean, Standard Deviation, and Total time a flow was actively sending packets


#### Idle Max, Min, Mean, Std, Total

Maximum, Minimum, Mean, Standard Deviation, and Total time a flow was idle before sending packets


#### Fwd, Bwd Init Win Bytes

The number of bytes sent in the initial window in the forward and backward directions


#### Fwd Act Data Pkts

Count of packets with at least 1 byte of TCP data payload in the forward direction


#### Fwd, Bwd Bytes Subflow

The average number of bytes in a subflow in the forward and backward directions Subflow Fwd Bytes The average number of bytes in a sub flow


#### Fwd, Bwd Packets Subflow

The average number of packets in a subflow in the forward and backward directions Subflow Fwd Bytes The average number of bytes in a sub flow


#### Flow Bytes/s

The bytes per second of a flow


####TTL Max, Min, Mean, Std, Total, Q1, Q2, Q3

Maximum, Minimum, Mean, Standard Deviation, Total, 1st, 2nd, and 3rd Quartiles in the Time-To-Live values of packets


#### Fwd TTL Max, Min, Mean, Std, Total, Q1, Q2, Q3

Maximum, Minimum, Mean, Standard Deviation, Total, 1st, 2nd, and 3rd Quartiles in the Time-To-Live values of packets send in the forward direction


#### Bwd TTL Max, Min, Mean, Std, Total, Q1, Q2, Q3

Maximum, Minimum, Mean, Standard Deviation, Total, 1st, 2nd, and 3rd Quartiles in the Time-To-Live values of packets send in the backward direction


--------------------------------------------------------------------------------------
