package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.features.FlowFeatures;

public interface FlowGenListener {
    void onFlowGenerated(FlowFeatures flow);
}
