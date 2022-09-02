package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.features.FlowPrediction;

import java.io.IOException;

public interface FlowGenListenerPrediction {
    void onFlowGeneratedPrediction(FlowPrediction flow) throws IOException;
}
