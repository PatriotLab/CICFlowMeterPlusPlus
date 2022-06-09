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
# Extracted Features and Descriptions

#### Common features include Maximum (Max), Minimum (Min), Mean (Average), Variance (Variance), Standard Deviation (Std), Total (Total), First Quartile (Q1), Second Quartile (Q2), and Third Quartile (Q3) 

<dl>
        <dt>Origin</dt>
    <dd>Source IP, Destination IP, Source Port, Destination Port, Protocol</dd>
        <dt>Source IP Address</dt>
    <dd>Source IP Address</dd>
        <dt>Source Port</dt>
    <dd>Source Port</dd>
        <dt>Source MAC Address</dt>
    <dd>Source MAC Address</dd>
        <dt>Destination IP Address</dt>
    <dd>Destination IP Address</dd>
        <dt>Destination Port</dt>
    <dd>Destination Port</dd>
        <dt>Destination MAC Address</dt>
    <dd>Destination MAC Address</dd>
        <dt>Timestamp</dt>
    <dd>Timestamp</dd>
        <dt>Duration</dt>
    <dd>Flow Duration</dd>
        <dt>Protocol</dt>
    <dd>Protocol</dd>
        <dt>Packet Count</dt>
    <dd>Total Number of Packets</dd>
        <dt>Fwd Packet Count</dt>
    <dd>Total Number of Packets in the Forward Direction</dd>
        <dt>Bwd Packet Count</dt>
    <dd>Total Number of Packets in the Backward Direction</dd>
        <dt>Packet Length Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Packet Length</dd>
        <dt>Header Length Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Header Length</dd>
        <dt>Fwd Packet Length Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Packet Length in the Forward Direction</dd>
        <dt>Fwd Header Length Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Header Length in the Forward Direction</dd>
        <dt>Bwd Packet Length Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Packet Length in the Backward Direction</dd>
        <dt>Bwd Header Length Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Header Length in the Backward Direction</dd>
        <dt>Count FIN Flag</dt>
    <dd>Number of FIN Flags Seen in a Flow</dd>
        <dt>Count PSH Flag</dt>
    <dd>Number of PSH Flags Seen in a Flow</dd>
        <dt>Count URG Flag</dt>
    <dd>Number of URG Flags Seen in a Flow</dd>
        <dt>Count ECE Flag</dt>
    <dd>Number of ECE Flags Seen in a Flow</dd>
        <dt>Count SYN Flag</dt>
    <dd>Number of SYN Flags Seen in a Flow</dd>
        <dt>Count ACK Flag</dt>
    <dd>Number of ACK Flags Seen in a Flow</dd>
        <dt>Count CWR Flag</dt>
    <dd>Number of CWR Flags Seen in a Flow</dd>
        <dt>Count RST Flag</dt>
    <dd>Number of RST Flags Seen in a Flow</dd>
        <dt>Fwd Count FIN Flag</dt>
    <dd>FIN Flags Sent in the Forward Direction</dd>
        <dt>Fwd Count PSH Flag</dt>
    <dd>PSH Flags Sent in the Forward Direction</dd>
        <dt>Fwd Count URG Flag</dt>
    <dd>URG Flags Sent in the Forward Direction</dd>
        <dt>Fwd Count ECE Flag</dt>
    <dd>ECE Flags Sent in the Forward Direction</dd>
        <dt>Fwd Count SYN Flag</dt>
    <dd>SYN Flags Sent in the Forward Direction</dd>
        <dt>Fwd Count ACK Flag</dt>
    <dd>ACK Flags Sent in the Forward Direction</dd>
        <dt>Fwd Count CWR Flag</dt>
    <dd>CWR Flags Sent in the Forward Direction</dd>
        <dt>Fwd Count RST Flag</dt>
    <dd>RST Flags Sent in the Forward Direction</dd>
        <dt>Bwd Count FIN Flag</dt>
    <dd>FIN Flags Sent in the Backward Direction</dd>
        <dt>Bwd Count PSH Flag</dt>
    <dd>PSH Flags Sent in the Backward Direction</dd>
        <dt>Bwd Count URG Flag</dt>
    <dd>URG Flags Sent in the Backward Direction</dd>
        <dt>Bwd Count ECE Flag</dt>
    <dd>ECE Flags Sent in the Backward Direction</dd>
        <dt>Bwd Count SYN Flag</dt>
    <dd>SYN Flags Sent in the Backward Direction</dd>
        <dt>Bwd Count ACK Flag</dt>
    <dd>ACK Flags Sent in the Backward Direction</dd>
        <dt>Bwd Count CWR Flag</dt>
    <dd>CWR Flags Sent in the Backward Direction</dd>
        <dt>Bwd Count RST Flag</dt>
    <dd>RST Flags Sent in the Backward Direction</dd>
        <dt>IAT Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Inter-Packet Arrival Time</dd>
        <dt>Fwd IAT Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Inter-Packet Arrival Time  in the Forward Direction</dd>
        <dt>Bwd IAT Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Inter-Packet Arrival Time  in the Backward Direction</dd>
        <dt>Active Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Active Time in a Flow Before Going Idle</dd>
        <dt>Idle Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Idle Time in a Flow Before Going Active</dd>
        <dt>FWD Init Win Bytes</dt>
    <dd>Number of Bytes Sent in the Initial Window in the Forward Direction</dd>
        <dt>Bwd Init Win Bytes</dt>
    <dd>Number of Bytes Sent in the Initial Window in the Backward Direction</dd>
        <dt>Fwd Act Data Pkts</dt>
    <dd>Number of Packets with at Least One Byte in the Payload in the Forward Direction</dd>
        <dt>Fwd Header Size Min</dt>
    <dd>Forward Header Size Minimum</dd>
        <dt>Fwd Bytes Subflow</dt>
    <dd>Total Bytes in Subflows in the forward Direction</dd>
        <dt>Fwd Packets Subflow</dt>
    <dd>Total Packets in Subflows in the Forward Direction</dd>
        <dt>Bwd Bytes Subflow</dt>
    <dd>Total Bytes in Subflows in the Backward Direction</dd>
        <dt>Bwd Packets Subflow</dt>
    <dd>Total Packets in Subflows in the Backward Direction</dd>
        <dt>Flow Bytes/s</dt>
    <dd>Bytes Per Second in the Flow</dd>
        <dt>TTL Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Time To Live Value</dd>
        <dt>Fwd TTL Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Time To Live Value in the Forward Direction</dd>
        <dt>Bwd TTL Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Time To Live Value in the Backward Direction</dd>
        <dt>HTTP Request Header Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>HTTP Request Header Length</dd>
        <dt>HTTP Request Payload Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>HTTP Request Payload Length</dd>
        <dt>HTTP Response Header Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>HTTP Response Header Length</dd>
        <dt>HTTP Response Payload Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>HTTP Response Payload Length</dd>
        <dt>HTTP IAT Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Inter-Packet Arrival Time Between HTTP Packets</dd>
        <dt>HTTP Server IAT Max, Min, Mean, Variance, Std, Total, Q1, Q2, Q3</dt>
    <dd>Inter-Packet Arrival Time Between HTTP Request and Response</dd>
</dl>
--------------------------------------------------------------------------------------
