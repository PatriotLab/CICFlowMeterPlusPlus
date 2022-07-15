package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import cic.cs.unb.ca.jnetpcap.PacketReader;
import cic.cs.unb.ca.jnetpcap.Protocol;
import cic.cs.unb.ca.jnetpcap.features.FlowFeatures;
import jakarta.xml.bind.JAXBException;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import javax.swing.*;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.util.List;

public class TrafficFlowWorker extends SwingWorker<String,String> implements FlowGenListener{

	public static final Logger logger = LoggerFactory.getLogger(TrafficFlowWorker.class);
    public static final String PROPERTY_FLOW = "flow";
	private String device;


    public TrafficFlowWorker(String device) {
		super();
		this.device = device;
	}

	@Override
	protected String doInBackground() {
		
		FlowGenerator   flowGen = new FlowGenerator(true,120000000L, 5000000L);
		flowGen.addFlowListener(this);
		int snaplen = 64 * 1024;//2048; // Truncate packet at this size
		int promiscous = Pcap.MODE_PROMISCUOUS;
		int timeout = 60 * 1000; // In milliseconds
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openLive(device, snaplen, promiscous, timeout, errbuf);
		if (pcap == null) {
			logger.info("open {} fail -> {}",device,errbuf.toString());
			return String.format("open %s fail ->",device)+errbuf.toString();
		}

		PcapPacketHandler<String> jpacketHandler = (packet, user) -> {

            /*
             * BufferUnderflowException while decoding header
             * that is because:
             * 1.PCAP library is not multi-threaded
             * 2.jNetPcap library is not multi-threaded
             * 3.Care must be taken how packets or the data they referenced is used in multi-threaded environment
             *
             * typical rule:
             * make new packet objects and perform deep copies of the data in PCAP buffers they point to
             *
             * but it seems not work
             */

			Protocol protocol = new Protocol();

            PcapPacket permanent = new PcapPacket(Type.POINTER);
            packet.transferStateAndDataTo(permanent);

			try {
				flowGen.addPacket(PacketReader.getBasicPacketInfo(permanent, true, false, protocol));
			} catch (JAXBException | IOException | ParserConfigurationException | SAXException e) {
				throw new RuntimeException(e);
			}
			if(isCancelled()) {
                pcap.breakloop();
                logger.debug("break Packet loop");
            }
        };

        //FlowMgr.getInstance().setListenFlag(true);
        logger.info("Pcap is listening...");
        firePropertyChange("progress","open successfully","listening: "+device);
        int ret = pcap.loop(Pcap.DISPATCH_BUFFER_FULL, jpacketHandler, device);

		return switch (ret) {
			case 0 -> "listening: " + device + " finished";
			case -1 -> "listening: " + device + " error";
			case -2 -> "stop listening: " + device;
			default -> String.valueOf(ret);
		};
	}

	@Override
	protected void process(List<String> chunks) {
		super.process(chunks);
	}

	@Override
	protected void done() {
		super.done();
	}

	@Override
	public void onFlowGenerated(FlowFeatures flow) {
        firePropertyChange(PROPERTY_FLOW,null,flow);
	}
}
