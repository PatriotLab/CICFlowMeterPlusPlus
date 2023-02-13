package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.CSVWriter;
import cic.cs.unb.ca.jnetpcap.features.Classifier;
import cic.cs.unb.ca.jnetpcap.features.FlowPrediction;

import java.io.File;

public class CaptureFactory {
    public void capture{
        CaptureFactory cap = CaptureFactory.openLive();
    }
    public interface FileCapture extends Capture<FilePacket>, FileIterator, java.io.Closeable{

    }
    public static CaptureFactory openLive() {

    }

    LiveCapture capture = CaptureFactory.openLive();
    while (capture.hasNext){
        CapturePacket = capture.next();
        //return packet byte[] to FeatureCollection?
    }

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


}
