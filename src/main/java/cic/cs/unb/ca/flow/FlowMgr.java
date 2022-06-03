package cic.cs.unb.ca.flow;

import cic.cs.unb.ca.jnetpcap.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;

public class FlowMgr {

    protected static final Logger logger = LoggerFactory.getLogger(FlowMgr.class);

    public static final String FLOW_SUFFIX = ".csv";

    private static FlowMgr Instance = new FlowMgr();

    private String mFlowSavePath;
    private String mDataPath;

    private FlowMgr() {
        super();
    }
    
    public static FlowMgr getInstance() {
        return Instance;
    }

    public FlowMgr init() {

        String rootPath = System.getProperty("user.dir");
		StringBuilder sb = new StringBuilder(rootPath);
		sb.append(Utils.FILE_SEP).append("data").append(Utils.FILE_SEP);

		mDataPath = sb.toString();

        sb.append("daily").append(Utils.FILE_SEP);
        mFlowSavePath = sb.toString();

        return Instance;
    }

    public void destroy() {
    }

	public String getSavePath() {
		return mFlowSavePath;
	}

    public String getmDataPath() {
        return mDataPath;
    }

    public String getAutoSaveFile() {
		String filename = LocalDate.now().toString();
		return mFlowSavePath+filename;
	}
}
