package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.features.FlowFeatures;

import java.io.IOException;

public interface FlowGenListener {
    void onFlowGenerated(FlowFeatures flow) throws IOException;
}
