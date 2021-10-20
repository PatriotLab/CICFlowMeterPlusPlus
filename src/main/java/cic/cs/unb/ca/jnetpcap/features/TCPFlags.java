package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class TCPFlags extends FeatureCollection {
    private int fin_count = 0;
    private int psh_count = 0;
    private int urg_count = 0;
    private int ece_count = 0;
    private int syn_count = 0;
    private int ack_count = 0;
    private int cwr_count = 0;
    private int rst_count = 0;

    public TCPFlags(){
        fields = new FeatureCollection.FieldBuilder()
                .addField(() -> fin_count, "Count FIN Flag")
                .addField(() -> psh_count, "Count PSH Flag")
                .addField(() -> urg_count, "Count URG Flag")
                .addField(() -> ece_count, "Count ECE Flag")
                .addField(() -> syn_count, "Count SYN Flag")
                .addField(() -> ack_count, "Count ACK FLag")
                .addField(() -> cwr_count, "Count CWR Flag")
                .addField(() -> rst_count, "Count RST Flag")
                .build();
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if(packet.hasFlagFIN()) fin_count++;
        if(packet.hasFlagPSH()) psh_count++;
        if(packet.hasFlagURG()) urg_count++;
        if(packet.hasFlagECE()) ece_count++;
        if(packet.hasFlagSYN()) syn_count++;
        if(packet.hasFlagACK()) ack_count++;
        if(packet.hasFlagCWR()) cwr_count++;
        if(packet.hasFlagRST()) rst_count++;
    }
}
