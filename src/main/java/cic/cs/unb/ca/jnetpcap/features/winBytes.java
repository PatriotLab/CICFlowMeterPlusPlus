package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class winBytes extends FeatureCollection{
    private int fwd_win_bytes = 0;
    private int bwd_win_bytes = 0;

    public winBytes() {
        fields = new FeatureCollection.FieldBuilder()
                .addField(() -> fwd_win_bytes, "FWD Init Win Bytes")
                .addField(() -> bwd_win_bytes, "Bwd Init Win Bytes")
                .build();
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        boolean isBackward = packet.isBwdPacket;
        int TCPWindow = packet.getTCPWindow();

        if(isBackward){
            if(bwd_win_bytes == 0){
                bwd_win_bytes = TCPWindow;
            }
        }
        else{
            if(fwd_win_bytes == 0){
                fwd_win_bytes = TCPWindow;
            }
        }

    }
}
