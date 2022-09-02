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
        /*List<String> flowStringList = new ArrayList<>();
        List<String[]> flowDataList = new ArrayList<>();
        String flowDump = String.join(",", flow.getData());
        flowStringList.add(flowDump);
        flowDataList.add(flow.getData(), ","));
//What's the difference between FlowPrediction and FlowFeatures?*/
		//List<String> flowStringList = new ArrayList<>();
		List<String[]> flowDataList = new ArrayList<>();
		String flowDump = Arrays.toString(flow.getData());
		//flowStringList.add(flowDump);
		flowDataList.add(StringUtils.split(flowDump, ","));

		SwingUtilities.invokeLater(new InsertTableRow(defaultTableModel,flowDataList));
		//write flows to csv file
		//String header  = FlowFeature.getHeader();
		//String path = FlowMgr.getInstance().getSavePath();
		//String filename = LocalDate.now().toString() + FlowMgr.FLOW_SUFFIX;
		//csvWriterThread.execute(new InsertCsvRow(header, flowStringList, path, filename));

		//FlowMonitorPane.updateFlowTable(flow);

		//write flows to csv file
        /*String header  = String.join(",", flowDump);
        String path = FlowMgr.getInstance().getSavePath();
        String filename = LocalDate.now().toString();
        CSVWriter<FlowPrediction> csv_writer = new CSVWriter<>(path+filename);
        /csvWriterThread.execute(new InsertCsvRow(header, flowStringList, path, filename));
		try {
			csv_writer.write(flow);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}*/

		//btnSave.setEnabled(true);
//		SwingUtilities.invokeLater(new InsertTableRow(defaultTableModel,flowDataList,lblFlowCnt));
	}

	/*@Override
	protected String doInBackground() {
		//To Do: Figure out how Swing workers work
		FlowGenerator flowGen = new FlowGenerator(120000000L, 5000000L);
		flowGen.addFlowListener(new FlowListener(csv_writer, classifierFile.toPath()));
//			flowGen.addFlowListener(this);
		int snaplen = 64 * 1024;//2048; // Truncate packet at this size
		int promiscous = Pcap.MODE_PROMISCUOUS;
		int timeout = 60 * 1000; // In milliseconds
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openLive(device, snaplen, promiscous, timeout, errbuf);

		if (pcap == null) {
			logger.info("open {} fail -> {}", device, errbuf);
			return String.format("open %s fail ->", device) + errbuf;
		} else if (classifier == null){
			classifierPresent = false;
		}

		PcapPacketHandler<String> jpacketHandler = (packet, user) -> {

			Protocol protocol = new Protocol();

			PcapPacket permanent = new PcapPacket(Type.POINTER);
			packet.transferStateAndDataTo(permanent);
			if(packet.hasHeader(protocol.ipv4())){
				ipv4 = true;
				ipv6 = false;
			} else {
				ipv4 = false;
				ipv6 = true;
			}

			try {
				flowGen.addPacket(PacketReader.getBasicPacketInfo(permanent, ipv4, ipv6, protocol));
				//flowGen.addFlowListener(new TrafficFlowWorker().FlowListener(csv_writer, classifierFile.toPath()));
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
			if (isCancelled()) {
				pcap.breakloop();
				logger.debug("break Packet loop");
			}
		};

		//FlowMgr.getInstance().setListenFlag(true);
		logger.info("Pcap is listening...");
		firePropertyChange("progress", "open successfully", "listening: " + device);
		int ret = pcap.loop(Pcap.DISPATCH_BUFFER_FULL, jpacketHandler, device);

		return switch (ret) {
			case 0 -> "listening: " + device + " finished";
			case -1 -> "listening: " + device + " error";
			case -2 -> "stop listening: " + device;
			default -> String.valueOf(ret);
		};
	}*/
    @Override
    protected String doInBackground() {
        //To Do: Figure out how Swing workers work
        FlowGenerator flowGen = new FlowGenerator(120000000L, 5000000L);
        flowGen.addFlowListener(new FlowListener(csv_writer, classifierFile.toPath()));
//			flowGen.addFlowListener(this);
        int snaplen = 64 * 1024;//2048; // Truncate packet at this size
        int promiscous = Pcap.MODE_PROMISCUOUS;
        int timeout = 60 * 1000; // In milliseconds
        StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openLive(device, snaplen, promiscous, timeout, errbuf);

        if (pcap == null) {
            logger.info("open {} fail -> {}", device, errbuf);
            return String.format("open %s fail ->", device) + errbuf;
        }
		if (classifier == null){
            classifierPresent = false;
        }

		// packet handler for packet capture
		Protocol protocol = new Protocol();

		pcap.loop(Integer.parseInt(args[1]), pcappackethandler, "pressure");
		pcap.loop(-1, new PcapPacketHandler<F>() {
		};

		if(packet.hasHeader(protocol.ipv4())){
			ipv4 = true;
			ipv6 = false;
		} else if(packet.hasHeader(protocol.ipv6())){
			ipv4 = false;
			ipv6 = true;
		}

		try {
			flowGen.addPacket(PacketReader.getBasicPacketInfo(permanent, ipv4, ipv6, protocol));
			//flowGen.addFlowListener(new TrafficFlowWorker().FlowListener(csv_writer, classifierFile.toPath()));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		if (isCancelled()) {
			pcap.breakloop();
			logger.debug("break Packet loop");
		}
		pcap.close();

        PcapPacketHandler<String> jpacketHandler = (packet, user) -> {


            PcapPacket permanent = new PcapPacket(Type.POINTER);
            packet.transferStateAndDataTo(permanent);

        };

        //FlowMgr.getInstance().setListenFlag(true);
        logger.info(device + " is listening...");
        firePropertyChange("progress", "open successfully", "listening: " + device);
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
