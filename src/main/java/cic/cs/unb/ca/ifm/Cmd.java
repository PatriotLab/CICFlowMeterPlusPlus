package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import cic.cs.unb.ca.jnetpcap.CSVWriter;
import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import cic.cs.unb.ca.jnetpcap.PacketReader;
import cic.cs.unb.ca.jnetpcap.features.Classifier;
import cic.cs.unb.ca.jnetpcap.features.FlowFeatures;
import cic.cs.unb.ca.jnetpcap.features.FlowPrediction;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import jakarta.xml.bind.JAXBException;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Cmd {

    public static final Logger logger = LoggerFactory.getLogger(Cmd.class);
    private static final String DividingLine = "-------------------------------------------------------------------------------";

    public static void main(String[] args) throws IOException {

        long flowTimeout = 120000000L;
        long activityTimeout = 5000000L;

        if(args.length < 2 || 3 < args.length){
            System.out.println("Usage: CICFlowMeter <interface> <outfile> [classifier]");
            System.out.println();
            System.out.println("List of available interfaces:");
            for(PcapIf pcap_if : Cmd.getPcapIfs()){
                System.out.printf("- %s%n", pcap_if.getName());
            }
            return;
        }

        String interface_name = args[0];

        String outPath = args[1];
        File out = new File(outPath);
        if (out.exists() && !out.isFile()) {
            logger.error("Could not create output file {}",outPath);
            return;
        }

        String classifierPath = null;
        if(args.length == 3){
            classifierPath = args[2];
        }

        readPcapFile(interface_name, outPath, classifierPath, flowTimeout, activityTimeout);

    }

    private static List<PcapIf> getPcapIfs(){
        StringBuilder errbuf = new StringBuilder();
        List<PcapIf> ifs = new ArrayList<>();
        if(Pcap.findAllDevs(ifs, errbuf)!=Pcap.OK) {
            logger.error("Error occurred: " + errbuf);
            throw new RuntimeException(errbuf.toString());
        }
        return ifs;
    }


    private static void readPcapFile(String interfaceName, String outPath, String classifierPath, long flowTimeout, long activityTimeout) throws IOException {
        if(interfaceName==null ||outPath==null ) {
            return;
        }

        File outFile = new File(outPath);
        if (outFile.exists()) {
           if (!outFile.delete()) {
               System.out.println("Output file can not be deleted");
           }
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        if(classifierPath != null){
            flowGen.addFlowListener(new ClassifierFlowListener(interfaceName, outPath, classifierPath));
        } else {
            flowGen.addFlowListener(new FlowListener(interfaceName, outPath));
        }
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = PacketReader.fromLive(interfaceName, readIP4, readIP6);

        System.out.printf("Working on... %s%n", interfaceName);

        int nValid=0;
        int nTotal=0;
        int nDiscarded = 0;

        Thread mainThread = Thread.currentThread();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                System.out.println("\nStopping...");
                packetReader.closeReader();
                mainThread.join();
            } catch (InterruptedException ex) {
                logger.error("Error while finishing:", ex);
            }
        }));

        while(true) {
            try{
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                nTotal++;
                if(basicPacket != null){
                    flowGen.addPacket(basicPacket);
                    nValid++;
                }else{
                    nDiscarded++;
                }
            }catch(PcapClosedException e){
                break;
            }
        }

        System.out.println("Processing existing flows...");

        flowGen.dumpLabeledCurrentFlow();

        System.out.printf("%s is done. total %d flows %n", interfaceName, 0);
        System.out.printf("Packet stats: Total=%d Valid=%d Discarded=%d%n",nTotal,nValid,nDiscarded);
        System.out.println(DividingLine);
    }

    static class FlowListener implements FlowGenListener {

        private final String name;
        private final CSVWriter<FlowFeatures> writer;

        public long cnt;

        public FlowListener(String name, String outPath) throws IOException {
            this.name = name;
            this.writer = new CSVWriter<>(outPath);
        }

        @Override
        public void onFlowGenerated(FlowFeatures flow) throws IOException {
            this.writer.write(flow);
            this.writer.flush();
            cnt++;
            System.out.printf("%s -> %d flows%n", name,cnt);
        }
    }

    static class ClassifierFlowListener implements FlowGenListener {
        private final String name;
        private final CSVWriter<FlowPrediction> writer;
        private final Classifier classifier;
        public long cnt;

        public ClassifierFlowListener(String name, String outPath, String classifierPath) throws IOException {
            this.name = name;
            this.writer = new CSVWriter<>(outPath);
            try {
                this.classifier = new Classifier(classifierPath);
            }catch (JAXBException | ParserConfigurationException | SAXException ex){
                throw new RuntimeException(ex);
            }
        }

        @Override
        public void onFlowGenerated(FlowFeatures flow) throws IOException {
            FlowPrediction prediction = classifier.predict(flow);
            this.writer.write(prediction);
            this.writer.flush();
            cnt++;
            System.out.printf("%s -> %d flows%n", name,cnt);
        }
    }


}
