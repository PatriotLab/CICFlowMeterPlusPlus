package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature returns the size of the fwd and bwd initial window size.
 *
 * @author Dylan Westlund
 */

public class WinBytes extends FeatureCollection{
    private int fwd_win_bytes = 0;
    private int bwd_win_bytes = 0;

    private boolean firstFwd = true;
    private boolean firstBwd = true;

    public WinBytes() {
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
            if(firstBwd == true){
                bwd_win_bytes = TCPWindow;
                firstBwd = false;
            }
        }
        else{
            if(firstFwd == true){
                fwd_win_bytes = TCPWindow;
                firstFwd = false;
            }
        }

    }
}
