package cic.cs.unb.ca.jnetpcap;

import org.apache.tika.Tika;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;

public class Utils {
    protected static final Logger logger = LoggerFactory.getLogger(Utils.class);
    public static final String FILE_SEP = System.getProperty("file.separator");
    public static final String LINE_SEP = System.lineSeparator();
    private final static String PCAP = "application/vnd.tcpdump.pcap";
    private final static String PMML = "application/octet-stream";
    private final static String PMML2 = "application/xml";
    public static final String FLOW_SUFFIX = ".csv";


    private static boolean isPcapFile(String contentType) {

        return PCAP.equalsIgnoreCase(contentType);
    }

    private static boolean detectPmmlFile(String contentType) {
        //Not sure which MIME type is correct, so I'm using both until we get CICFM working and test it.
        return (PMML.equalsIgnoreCase(contentType) || PMML2.equalsIgnoreCase(contentType));
    }

    public static boolean isPcapFile(File file) {

        if (file == null) {
            return false;
        }

        try {

            //Files.probeContentType returns null on Windows
            /*Path filePath = Paths.get(file.getPath());
            contentType = Files.probeContentType(filePath);*/

            return isPcapFile(new Tika().detect(file));

        } catch (IOException e) {
            logger.debug(e.getMessage());
        }

        return false;
    }

    public static boolean detectPmmlFile(File pmml) {

        if (pmml == null) {
            return false;
        }

        try {
            return detectPmmlFile(new Tika().detect(pmml));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static long countLines(String fileName) {
        File file =new File(fileName);
        int linenumber = 0;
        FileReader fr;
        LineNumberReader lnr = null;
        try {
            fr = new FileReader(file);
            lnr = new LineNumberReader(fr);

            while (lnr.readLine() != null){
                linenumber++;
            }

        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {

            if (lnr != null) {

                try {
                    lnr.close();
                } catch (IOException e) {
                    logger.debug(e.getMessage());
                }
            }
        }
        return linenumber;
    }

}
