package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class Ratio extends FeatureCollection{
    private int Fwd;
    private int Bwd;

    //private final HashMap<Float, Integer> values = new HashMap<>();

    public Ratio() {
        new FieldBuilder()
                .addField(() -> (double) Bwd/Fwd, "Bwd/Fwd Ratio")
                .build(this);
    }

    public void onPacket(BasicPacketInfo packet) {
        if(packet.isBwdPacket){
            Bwd++;
        }
        else {
            Fwd++;
        }
    }
}