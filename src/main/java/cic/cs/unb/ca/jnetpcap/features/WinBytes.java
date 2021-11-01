package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class WinBytes extends FeatureCollection{
    private int fwd_win_bytes = -1;
    private int bwd_win_bytes = -1;

    public WinBytes() {
        if(bwd_win_bytes == -1){
            bwd_win_bytes = 0;
        }
        if(fwd_win_bytes == -1){
            fwd_win_bytes = 0;
        }
        new FeatureCollection.FieldBuilder()
                .addField(() -> fwd_win_bytes, "FWD Init Win Bytes")
                .addField(() -> bwd_win_bytes, "Bwd Init Win Bytes")
                .build(this);
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
