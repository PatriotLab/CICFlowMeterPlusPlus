package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.features.FlowFeatures;
import cic.cs.unb.ca.jnetpcap.features.FlowPrediction;

import java.io.IOException;

public interface FlowGenListener {
    void onFlowGenerated(FlowFeatures flow) throws IOException;
}
