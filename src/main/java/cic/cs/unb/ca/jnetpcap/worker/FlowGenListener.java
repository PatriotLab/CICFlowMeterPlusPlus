package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.features.FlowFeatures;
import jakarta.xml.bind.JAXBException;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;

public interface FlowGenListener {
    void onFlowGenerated(FlowFeatures flow) throws JAXBException, IOException, ParserConfigurationException, SAXException;
}
