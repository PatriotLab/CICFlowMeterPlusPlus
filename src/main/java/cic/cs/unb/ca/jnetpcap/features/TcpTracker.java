package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature that tracks flow status.
 *
 * @author Michael Fahnlander
 */

public class TcpTracker extends FeatureCollection{
    public Boolean Fin = false;
    public Boolean FinAck = false;
    public static Boolean FlowEnded = false;
    @Override
    public void onPacket(BasicPacketInfo packet) {
        //Checks for TCP flags indicating a TCP teardown sequence
        if(packet.isForwardPacket() && packet.hasFlagFIN()){
            Fin = true;
        }
        if(Fin && packet.isBwdPacket && packet.hasFlagACK() && packet.hasFlagFIN()){
            FinAck = true;
        }
        if(FinAck && packet.isForwardPacket() && packet.hasFlagACK()){
            FlowEnded = true;
        }
    }
}