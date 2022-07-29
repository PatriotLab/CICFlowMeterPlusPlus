package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.*;
import cic.cs.unb.ca.jnetpcap.features.Classifier;
import cic.cs.unb.ca.jnetpcap.features.FlowFeatures;
import cic.cs.unb.ca.jnetpcap.features.FlowPrediction;
import jakarta.xml.bind.JAXBException;
import org.apache.commons.io.FilenameUtils;
import org.jnetpcap.PcapClosedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import javax.swing.*;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static cic.cs.unb.ca.jnetpcap.Utils.*;


public class ReadPcapFileWorker extends SwingWorker<List<String>,String> {

    public static final Logger logger = LoggerFactory.getLogger(ReadPcapFileWorker.class);
    public static final String PROPERTY_FILE_CNT = "file_count";
    public static final String PROPERTY_CUR_FILE = "file_current";
    public static final String PROPERTY_FLOW = "file_flow";
    private static final String DividingLine = "---------------------------------------------------------------------------------------------------------------";

    private long flowTimeout;
    private long activityTimeout;
    private int     totalFlows = 0;
    
    private File pcapPath;
    private String outPutDirectory;
    private CSVWriter<FlowPrediction> outputWriter;
    private File classifier;
    private List<String> chunks;


    public ReadPcapFileWorker(File inputFile, CSVWriter<FlowPrediction> writer, long param1, long param2, File inputClassifier) {
        super();
        pcapPath = inputFile;
        outputWriter = writer;
        classifier = inputClassifier;
        chunks = new ArrayList<>();

//        if(!outPutDirectory.endsWith(FILE_SEP)) {
//            outPutDirectory = outPutDirectory + FILE_SEP;
//        }
        flowTimeout = param1;
        activityTimeout = param2;
    }

    @Override
    protected List<String> doInBackground() {
        try {
            if (pcapPath.isDirectory() && detectPmmlFile(classifier)) {
                readPcapDir(pcapPath, outPutDirectory);
            } else {

                if (!isPcapFile(pcapPath)) {
                    publish("Please select pcap file!");
                    publish("");
                } else if (!detectPmmlFile(classifier)){
                    publish("Please select classifier file!");
                    publish("");
                }
                else {
                    publish("CICFlowMeter received 1 pcap file");
                    publish("");
                    publish("");

                    firePropertyChange(PROPERTY_CUR_FILE, "", pcapPath.getName());
                    firePropertyChange(PROPERTY_FILE_CNT, 1, 1);//begin with 1
                    readPcapFile(pcapPath.getPath(), outPutDirectory);
                }
            }
        } catch(Throwable e){
            publish("Encountered exception ", e.toString());
            logger.error("encountered exception", e);
        }

        return chunks;
    }

    @Override
    protected void done() {
        super.done();
    }

    @Override
    protected void process(List<String> chunks) {
        super.process(chunks);
        firePropertyChange("progress","",chunks);
    }

    private void readPcapDir(File inputPath, String outPath) throws IOException {
        if(inputPath==null||outPath==null) {
            return;
        }

        //File[] pcapFiles = inputPath.listFiles(file -> file.getName().toLowerCase().endsWith("pcap"));
        File[] pcapFiles = inputPath.listFiles(file -> isPcapFile(file));

        int file_cnt = pcapFiles.length;
        logger.debug("CICFlowMeter found :{} pcap files", file_cnt);
        publish(String.format("CICFlowMeter found :%s pcap files", file_cnt));
        publish("");
        publish("");

        for(int i=0;i<file_cnt;i++) {
            File file = pcapFiles[i];
            if (file.isDirectory()) {
                continue;
            }
            firePropertyChange(PROPERTY_CUR_FILE,"",file.getName());
            firePropertyChange(PROPERTY_FILE_CNT,file_cnt,i+1);//begin with 1
            readPcapFile(file.getPath(),outPath);
        }

    }

    private void readPcapFile(String inputFile, String outPath) throws IOException {
//        if(inputFile==null ||outPath==null ) {
//            return;
//        }

        Path p = Paths.get(inputFile);
        String fileName = p.getFileName().toString();//FilenameUtils.getName(inputFile);


//        if(!outPath.endsWith(FILE_SEP)){
//            outPath += FILE_SEP;
//        }

//        File saveFileFullPath = new File(outPath+ FilenameUtils.removeExtension(fileName)+Utils.FLOW_SUFFIX);

//        if (saveFileFullPath.exists()) {
//            if (!saveFileFullPath.delete()) {
//                System.out.println("Saved file full path cannot be deleted");
//            }
//        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        flowGen.addFlowListener(new FlowListener(fileName, classifier.toPath()));
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);
        publish(String.format("Working on... %s",inputFile));
        logger.debug("Working on... {}",inputFile);

        int nValid=0;
        int nTotal=0;
        int nDiscarded = 0;
        long start = System.currentTimeMillis();
        while(true) {
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
            }
        }
        flowGen.dumpLabeledCurrentFlow("");

        outputWriter.close();

//        long lines = countLines(saveFileFullPath.getPath());

        long end = System.currentTimeMillis();

        chunks.clear();
//        chunks.add(String.format("Done! Total %d flows",lines));
        chunks.add(String.format("Packets stats: Total=%d,Valid=%d,Discarded=%d",nTotal,nValid,nDiscarded));
        chunks.add(DividingLine);
        publish(chunks.toArray( new String[chunks.size()]));

    }


    class FlowListener implements FlowGenListener {

        private String fileName;
        private Classifier classifier;

        FlowListener(String fileName, Path modelName) {
            this.fileName = fileName;
            try {
                this.classifier = new Classifier(modelName.toString());
            } catch(Exception e) {
                logger.error("Couldn't load model", e);
                throw new RuntimeException();
            }
        }

        @Override
        public void onFlowGenerated(FlowFeatures flow) {
            FlowPrediction prediction = classifier.predict(flow);
            firePropertyChange(PROPERTY_FLOW,fileName,prediction);
        }
    }

}
