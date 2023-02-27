package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import cic.cs.unb.ca.jnetpcap.PacketReader;
import cic.cs.unb.ca.jnetpcap.features.FlowFeatures;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;
import jakarta.xml.bind.JAXBException;
import org.apache.commons.io.FilenameUtils;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;
import swing.common.SwingUtils;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static cic.cs.unb.ca.jnetpcap.Utils.FILE_SEP;
import static cic.cs.unb.ca.jnetpcap.Utils.FLOW_SUFFIX;

public class Cmd {

    public static final Logger logger = LoggerFactory.getLogger(Cmd.class);
    private static final String DividingLine = "-------------------------------------------------------------------------------";
    private static String[] animationChars = new String[]{"|", "/", "-", "\\"};

    public static void main(String[] args) {

        long flowTimeout = 120000000L;
        long activityTimeout = 5000000L;
        String rootPath = System.getProperty("user.dir");
        String pcapPath;
        String outPath;

        /* Select path for reading all .pcap files */
        /*if(args.length<1 || args[0]==null) {
            pcapPath = rootPath+"/data/in/";
        }else {
        }*/

        /* Select path for writing all .csv files */
        /*if(args.length<2 || args[1]==null) {
            outPath = rootPath+"/data/out/";
        }else {
        }*/

//        FlowFeatures.enableColumnCompat = Boolean.parseBoolean(args[2]);
//        logger.info("Enabled Column Compat -> {}", FlowFeatures.enableColumnCompat);


        if (args.length < 1) {
            System.out.println("Select an interface:");

            List<PcapIf> ifs = Cmd.getPcapIfs();
            for(PcapIf pcap_if : ifs){
                System.out.printf("- %s\n", pcap_if.getName());
            }
            return;
        }

        String interface_name = args[0];
        System.out.printf("interface name: %s\n", interface_name);

        if (args.length < 2) {
            logger.error("Please select output folder!");
            return;
        }
        outPath = args[1];
        File out = new File(outPath);
        if (out == null || out.isFile()) {
            logger.error("The out folder does not exist! -> {}",outPath);
            return;
        }

        logger.info("You select: {}",interface_name);
        logger.info("Out folder: {}",outPath);

        logger.info("CICFlowMeter received 1 pcap file");
        readPcapFile(interface_name, outPath,flowTimeout,activityTimeout);

    }

    private static List<PcapIf> getPcapIfs(){
        StringBuilder errbuf = new StringBuilder();
        List<PcapIf> ifs = new ArrayList<>();
        if(Pcap.findAllDevs(ifs, errbuf)!=Pcap.OK) {
            logger.error("Error occurred: " + errbuf.toString());
            throw new RuntimeException(errbuf.toString());
        }
        return ifs;
    }

    private static void readPcapFile(String inputFile, String outPath, long flowTimeout, long activityTimeout) {
        if(inputFile==null ||outPath==null ) {
            return;
        }
        String fileName = FilenameUtils.removeExtension(FilenameUtils.getName(inputFile));

        if(!outPath.endsWith(FILE_SEP)){
            outPath += FILE_SEP;
        }

        File saveFileFullPath = new File(outPath+fileName + FLOW_SUFFIX);

        if (saveFileFullPath.exists()) {
           if (!saveFileFullPath.delete()) {
               System.out.println("Save file can not be deleted");
           }
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        flowGen.addFlowListener(new FlowListener(fileName,outPath));
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = PacketReader.fromLive(inputFile, readIP4, readIP6);

        System.out.println(String.format("Working on... %s",fileName));

        int nValid=0;
        int nTotal=0;
        int nDiscarded = 0;
        long start = System.currentTimeMillis();
        int i=0;
        while(true) {
            /*i = (i)%animationChars.length;
            System.out.print("Working on "+ inputFile+" "+ animationChars[i] +"\r");*/
            try{
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                nTotal++;
                if(basicPacket !=null){
                    flowGen.addPacket(basicPacket);
                    nValid++;
                }else{
                    nDiscarded++;
                }
            }catch(PcapClosedException e){
                break;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            i++;
        }

        flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath());

        long lines = SwingUtils.countLines(saveFileFullPath.getPath());

        System.out.println(String.format("%s is done. total %d flows ",fileName,lines));
        System.out.println(String.format("Packet stats: Total=%d,Valid=%d,Discarded=%d",nTotal,nValid,nDiscarded));
        System.out.println(DividingLine);

        //long end = System.currentTimeMillis();
        //logger.info(String.format("Done! in %d seconds",((end-start)/1000)));
        //logger.info(String.format("\t Total packets: %d",nTotal));
        //logger.info(String.format("\t Valid packets: %d",nValid));
        //logger.info(String.format("\t Ignored packets:%d %d ", nDiscarded,(nTotal-nValid)));
        //logger.info(String.format("PCAP duration %d seconds",((packetReader.getLastPacket()- packetReader.getFirstPacket())/1000)));
        //int singleTotal = flowGen.dumpLabeledFlowBasedFeatures(outPath, fileName+ FlowMgr.FLOW_SUFFIX, FlowFeature.getHeader());
        //logger.info(String.format("Number of Flows: %d",singleTotal));
        //logger.info("{} is done,Total {} flows",inputFile,singleTotal);
        //System.out.println(String.format("%s is done,Total %d flows", inputFile, singleTotal));
    }

    static class FlowListener implements FlowGenListener {

        private String fileName;

        private String outPath;

        private long cnt;

        public FlowListener(String fileName, String outPath) {
            this.fileName = fileName + FLOW_SUFFIX;
            this.outPath = outPath;
        }

        @Override
        public void onFlowGenerated(FlowFeatures flow) {

            String flowDump = String.join(",", flow.getData());
            List<String> flowStringList = new ArrayList<>();
            flowStringList.add(flowDump);
            InsertCsvRow.insert(String.join(",", flow.getHeader()),flowStringList,outPath,fileName);

            cnt++;

            String console = String.format("%s -> %d flows \r", fileName,cnt);

            System.out.print(console);
        }
    }

}
