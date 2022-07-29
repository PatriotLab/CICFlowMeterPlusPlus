package cic.cs.unb.ca.jnetpcap;

import cic.cs.unb.ca.jnetpcap.features.FeatureCollection;
import cic.cs.unb.ca.jnetpcap.features.FlowFeatures;
import cic.cs.unb.ca.jnetpcap.features.TcpTracker;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;

import static cic.cs.unb.ca.jnetpcap.Utils.LINE_SEP;

public class FlowGenerator {
    public static final Logger logger = LoggerFactory.getLogger(FlowGenerator.class);

    private FlowGenListener mListener;
    private LinkedHashMap<String, FlowFeatures> currentFlows;
    private HashMap<Integer, FlowFeatures> finishedFlows;
    private FlowFeatures someFlow;
//	private HashMap<String,ArrayList> IPAddresses;

    //	private boolean bidirectional;
    private long flowTimeOut;
    private long flowActivityTimeOut;
    private int finishedFlowCount;

    public FlowGenerator(boolean bidirectional, long flowTimeout, long activityTimeout) {
        super();
//		this.bidirectional = bidirectional;
        this.flowTimeOut = flowTimeout;
        this.flowActivityTimeOut = activityTimeout;
        init();
    }

    private void init() {
        currentFlows = new LinkedHashMap<>(16, 0.75F, false);
        finishedFlows = new HashMap<>();
        finishedFlowCount = 0;
    }

    public void addFlowListener(FlowGenListener listener) {
        mListener = listener;
    }

    public void addPacket(BasicPacketInfo packet) throws IOException {
        if (packet == null) {
            return;
        }

        long currentTimestamp = packet.getTimeStamp();

        ArrayList<String> removedFlows = new ArrayList<>();
        for (Map.Entry<String, FlowFeatures> entry : this.currentFlows.entrySet()){

            FlowFeatures flow = entry.getValue();
            if((currentTimestamp - flow.times.getStartTime()) > flowTimeOut) {
                if(flow.packet_count.total.count > 1){
                    if (mListener != null) {
                        mListener.onFlowGenerated(flow);
                    } else {
                        finishedFlows.put(getFlowCount(), flow);
                    }
                }
                removedFlows.add(entry.getKey());
            } else {
                break;
            }
        }
        for(String flowId : removedFlows) {
            currentFlows.remove(flowId);
        }

        if (this.currentFlows.containsKey(packet.fwdFlowId()) || this.currentFlows.containsKey(packet.bwdFlowId())) {
            String id;
            if (this.currentFlows.containsKey(packet.fwdFlowId())) {
                id = packet.fwdFlowId();
            } else {
                id = packet.bwdFlowId();
            }

            FlowFeatures flow = currentFlows.get(id);

            // Flow finished due flowtimeout:
            // 1.- we move the flow to finished flow list
            // 2.- we eliminate the flow from the current flow list
            // 3.- we create a new flow with the packet-in-process
            if ((currentTimestamp - flow.times.getStartTime()) > flowTimeOut) {
                if (flow.packet_count.total.count > 1) {
                    if (mListener != null) {
                        mListener.onFlowGenerated(flow);
                    } else {
                        finishedFlows.put(getFlowCount(), flow);
                    }
//                    flow.endActiveIdleTime(currentTimestamp,this.flowActivityTimeOut, this.flowTimeOut, false);
                }
                currentFlows.remove(id);
//				currentFlows.put(id, new BasicFlow(bidirectional,packet,flow.getSrc(),flow.getDst(),flow.getSrcPort(),flow.getDstPort(), this.flowActivityTimeOut));
                currentFlows.put(id, new FlowFeatures(packet, this.flowActivityTimeOut));

                int cfsize = currentFlows.size();
                if (cfsize % 50 == 0) {
                    logger.debug("Timeout current has {} flow", cfsize);
                }

                // Flow finished due TCP teardown sequence:
                // 1.- we add the packet-in-process to the flow (it is the last packet)
                // 2.- we move the flow to finished flow list
                // 3.- we eliminate the flow from the current flow list
            } else if (TcpTracker.FlowEnded) {
                logger.debug("FlagFIN current has {} flow", currentFlows.size());
                flow.onPacket(packet);
                if (mListener != null) {
                    mListener.onFlowGenerated(flow);
                } else {
                    finishedFlows.put(getFlowCount(), flow);
                }
                currentFlows.remove(id);
            } else {
//    			flow.updateActiveIdleTime(currentTimestamp,this.flowActivityTimeOut);
                flow.onPacket(packet);
                currentFlows.put(id, flow);
            }
        } else {
            FlowFeatures new_flow = new FlowFeatures(packet, this.flowActivityTimeOut);
            someFlow = new_flow;
            currentFlows.put(packet.fwdFlowId(), new_flow);
        }
    }

    public int dumpLabeledFlowBasedFeatures(String path, String filename) {
        FlowFeatures flow;
        int total = 0;
        int zeroPkt = 0;

        try {
            total = finishedFlows.size() + currentFlows.size(); //becasue there are 0 packet BasicFlow in the currentFlows

//            FileOutputStream output = new FileOutputStream(new File(path + filename));
//            logger.debug("dumpLabeledFlow: ", path + filename);
//            output.write((someFlow.dumpHeader() + "\n").getBytes());
            Set<Integer> fkeys = finishedFlows.keySet();
            for (Integer key : fkeys) {
                flow = finishedFlows.get(key);
                if (flow.packet_count.total.count > 1) {
                    mListener.onFlowGenerated(flow);
//                    output.write((flow.dumpFlowBasedFeaturesEx() + "\n").getBytes());
                    total++;
                } else {
                    zeroPkt++;
                }
            }
            logger.debug("dumpLabeledFlow finishedFlows -> {},{}", zeroPkt, total);

            Set<String> ckeys = currentFlows.keySet();
//            output.write((someFlow.dumpHeader() + "\n").getBytes());
            for (String key : ckeys) {
                flow = currentFlows.get(key);
                if (flow.packet_count.total.count > 1) {
                    mListener.onFlowGenerated(flow);
//                    output.write((flow.dumpFlowBasedFeaturesEx() + "\n").getBytes());
                    total++;
                } else {
                    zeroPkt++;
                }

            }
            logger.debug("dumpLabeledFlow total(include current) -> {},{}", zeroPkt, total);
//            output.flush();
//            output.close();
        } catch (IOException e) {

            logger.debug(e.getMessage());
        }

        return total;
    }

    public long dumpLabeledCurrentFlow(String fileFullPath) {
        if (fileFullPath == null) {
            String ex = String.format("fullFilePath=%s,filename=%s", fileFullPath);
            throw new IllegalArgumentException(ex);
        }

//        File file = new File(fileFullPath);
//        FileOutputStream output = null;
        int total = 0;
        try {
//            if (file.exists()) {
//                output = new FileOutputStream(file, true);
//            } else {
//                if (file.createNewFile()) {
//                    output = new FileOutputStream(file);
//                    output.write((someFlow.dumpHeader() + LINE_SEP).getBytes());
//                }
//            }
            for (FlowFeatures flow : currentFlows.values()) {
                mListener.onFlowGenerated(flow);
            }

        } catch (IOException e) {
            logger.debug(e.getMessage());
        }
        return total;
    }

    private int getFlowCount() {
        this.finishedFlowCount++;
        return this.finishedFlowCount;
    }
}
