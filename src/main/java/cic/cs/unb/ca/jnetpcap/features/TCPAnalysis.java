package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class TCPAnalysis extends FeatureCollection{
    private boolean duplicateACK = false;
    private int duplicateACKCount = 0;

    public TCPAnalysis() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> duplicateACKCount, "Duplicate ACK")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if(packet.hasFlagACK() && duplicateACK){
            duplicateACKCount++;
        }
        if(packet.hasFlagACK()){
            duplicateACK = true;
        }
        else{
            duplicateACK = false;
        }
    }
}
