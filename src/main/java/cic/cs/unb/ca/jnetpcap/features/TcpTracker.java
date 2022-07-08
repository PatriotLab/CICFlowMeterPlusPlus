package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature that tracks flow status.
 *
 * @author Michael Fahnlander
 */

public class TcpTracker extends FeatureCollection{
    public Boolean FwdFin = false;
    public Boolean BwdAck = false;
    public Boolean BwdFinAck = false;
    public static Boolean FlowEnded = false;
    @Override
    public void onPacket(BasicPacketInfo packet) {
        //Checks for TCP flags indicating a TCP teardown sequence
        if(packet.isFwdPacket() && packet.hasFlagFIN()){
            //Close-Wait
            FwdFin = true;
        }
        if(FwdFin && packet.isBwdPacket() && packet.hasFlagACK()){
            //Ack Close-Wait FIN
            BwdAck = true;
        }
        if(BwdAck && packet.isBwdPacket() && packet.hasFlagACK() && packet.hasFlagFIN()){
            //FIN-Wait 2
            BwdFinAck = true;
        }
        if(packet.hasFlagRST() || BwdFinAck && packet.isFwdPacket() && packet.hasFlagACK()){
            //TCP flow closed
            FlowEnded = true;
        }
    }
}