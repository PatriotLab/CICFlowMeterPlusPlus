package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.CSVWriter;
import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import cic.cs.unb.ca.jnetpcap.PacketReader;
import cic.cs.unb.ca.jnetpcap.Protocol;
import cic.cs.unb.ca.jnetpcap.features.Classifier;
import cic.cs.unb.ca.jnetpcap.features.FeatureCollection;
import cic.cs.unb.ca.jnetpcap.features.FlowFeatures;
import cic.cs.unb.ca.jnetpcap.features.FlowPrediction;
import org.apache.commons.lang3.StringUtils;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import swing.common.InsertTableRow;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TrafficFlowWorker extends SwingWorker<String,String> {

	public static final Logger logger = LoggerFactory.getLogger(TrafficFlowWorker.class);
	public static final String PROPERTY_FLOW = "flow";
	public static DefaultTableModel defaultTableModel;
	public boolean ipv4;
	public boolean ipv6;
	public final String device;
	public final File classifierFile;
	public CSVWriter<FlowPrediction> csv_writer;
	public Classifier classifier;
	public Boolean classifierPresent;

    public TrafficFlowWorker(String listenDevice, File classifierParam, CSVWriter<FlowPrediction> writer) {
		super();
		device = listenDevice;
		classifierFile = classifierParam;
		csv_writer = writer;
		try {
			classifier = new Classifier(classifierParam.toString());
		} catch(Exception e) {
			logger.error("Couldn't load model", e);
			throw new RuntimeException();
		}
	}

	public static void insertFlowFeatures(FlowPrediction flow) {

		List<String[]> flowDataList = new ArrayList<>();
		String flowDump = Arrays.toString(flow.getData());
		//flowStringList.add(flowDump);
		flowDataList.add(StringUtils.split(flowDump, ","));

		SwingUtilities.invokeLater(new InsertTableRow(defaultTableModel, flowDataList));
	}
    @Override
    protected String doInBackground() {
        FlowGenerator flowGen = new FlowGenerator(120000000L, 5000000L);
        flowGen.addFlowListener(new FlowListener(csv_writer, classifierFile.toPath()));
        int snaplen = 65536; // 64 * 1024 Truncate packet at this size
        int promiscuous = Pcap.MODE_PROMISCUOUS;
        int timeout = 60000; //60 * 1000 milliseconds
        StringBuilder errbuf = new StringBuilder();
        Pcap selectedInterface = Pcap.openLive(device, snaplen, promiscuous, timeout, errbuf);

        if (selectedInterface == null) {
            logger.info("open {} fail -> {}", device, errbuf);
            return String.format("open %s fail ->", device) + errbuf;
        }

		// packet handler for packet capture
		Protocol protocol = new Protocol();

		//selectedInterface.loop(-1, new PcapPacketHandler<F>() {
		while ( selectedInterface.hasNext()){
		PcapPacket packet = selectedInterface.nextEx();
		try {
			flowGen.addPacket(PacketReader.getBasicPacketInfo(packet, ipv4, ipv6, protocol));
			//flowGen.addFlowListener(new TrafficFlowWorker().FlowListener(csv_writer, classifierFile.toPath()));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		if (isCancelled()) {
			selectedInterface.breakloop();
			logger.debug("break Packet loop");
			selectedInterface.close();
		}

        PcapPacketHandler<String> jpacketHandler = (jpacket, user) -> {

            PcapPacket permanent = new PcapPacket(Type.POINTER);
            jpacket.transferStateAndDataTo(permanent);
        };

        //FlowMgr.getInstance().setListenFlag(true);
        int ret = selectedInterface.loop(Pcap.DISPATCH_BUFFER_FULL, jpacketHandler, device);
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

	static class FlowListener implements FlowGenListener {

		private final CSVWriter<FlowPrediction> writer;
		private final Classifier classifier;

		FlowListener(CSVWriter<FlowPrediction> writer, Path modelName) {
			this.writer = writer;
			try {
				classifier = new Classifier(modelName.toString());
			} catch(Exception e) {
				logger.error("Couldn't load model", e);
				throw new RuntimeException();
			}
		}

		@Override
		public void onFlowGenerated(FlowFeatures flow) throws IOException {
			FlowPrediction prediction = classifier.predict(flow);
			insertFlowFeatures(prediction);
			writer.write(prediction);
		}
	}
}
