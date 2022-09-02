package cic.cs.unb.ca.flow.ui;

import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.CSVWriter;
import cic.cs.unb.ca.jnetpcap.PcapIfWrapper;
import cic.cs.unb.ca.jnetpcap.Utils;
import cic.cs.unb.ca.jnetpcap.features.FlowFeatures;
import cic.cs.unb.ca.jnetpcap.features.FlowPrediction;
import cic.cs.unb.ca.jnetpcap.worker.LoadPcapInterfaceWorker;
import cic.cs.unb.ca.jnetpcap.worker.TrafficFlowWorker;
import org.apache.commons.lang3.StringUtils;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import swing.common.JTable2CSVWorker;
import swing.common.PmmlFileFilter;
import swing.common.TextFileFilter;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;

public class FlowMonitorPane extends JPanel {
    protected final Logger logger = LoggerFactory.getLogger(FlowMonitorPane.class);

    public JTable flowTable;
    private Vector<File> classifierEle;
    private JComboBox<File> classifierBox;
    private final PmmlFileFilter pmmlChooserFilter = new PmmlFileFilter();
    public static File chosenClassifier;
    private DefaultTableModel defaultTableModel;
    private JList<PcapIfWrapper> list;
    private DefaultListModel<PcapIfWrapper> listModel;
    private JLabel lblStatus;
    private TrafficFlowWorker mWorker;
    private JButton btnLoad;
    private JToggleButton btnStart;
    public JToggleButton btnStop;
    private ButtonGroup btnGroup;
    private final JLabel classifierLabel = new JLabel("Classifier:");
    private final JButton browseClassifiers = new JButton("Browse");
    //private JButton btnSave = new JButton();
    //private JButton btnGraph = new JButton();
    private JFileChooser pmmlChooser;
    public static String[] completeHeaders;

    //private ExecutorService csvWriterThread;
    //private final String path = FlowMgr.getInstance().getSavePath();

    public FlowMonitorPane() throws IOException {
        //init();
        //add(initTablePane());
        //add(initFlowPane());
        add(initCenterPane(), BorderLayout.CENTER);
    }

    private void setComboBox(JComboBox<File> combo, Vector<File> comboEle, File ele) {
        if (comboEle.contains(ele)) {
            combo.setSelectedItem(ele);
        } else {
            comboEle.addElement(ele);
            combo.setSelectedItem(comboEle.lastElement());
        }
    }
    /*private void init() {
        pmmlChooser =
        //csvWriterThread = Executors.newSingleThreadExecutor();
    }

    public void destroy() {
        csvWriterThread.shutdown();
    }*/

    public JPanel initCenterPane(){
        JPanel livePane = new JPanel();
        livePane.setLayout(new BorderLayout(0, 0));
        livePane.setBorder(BorderFactory.createEmptyBorder(0,0,0,0));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,initFlowPane(), initNWifsPane());
        splitPane.setBorder(BorderFactory.createEmptyBorder(0,0,0,0));
        splitPane.setOneTouchExpandable(true);
        splitPane.setResizeWeight(1.0);

        livePane.add(splitPane,BorderLayout.CENTER);
        return livePane;
    }

    private JPanel initFlowPane() {
        JPanel pane = new JPanel();
        pane.setLayout(new BorderLayout(0, 5));
        pane.setBorder(BorderFactory.createLineBorder(new Color(0x555555)));

        pane.add(initClassifierPane(), BorderLayout.NORTH);
        pane.add(initTablePane(), BorderLayout.CENTER);
        pane.add(initStatusPane(), BorderLayout.SOUTH);

        return pane;
    }

    private JPanel initTablePane() {
        JPanel pane = new JPanel();
        JScrollPane scrollPane;
        pane.setLayout(new BorderLayout(0, 0));
        pane.setBorder(BorderFactory.createEmptyBorder(0,0,0,0));

        FlowFeatures headers = new FlowFeatures();
//        ArrayList<String> test = Arrays.stream(headers.getHeader()).toArray();
        String[] headerList = headers.getHeader();
        //String[] arrayHeader = StringUtils.split(headers, ",");
        //test.add(0, "Accuracy");
        //test.add(0, "Label");
        //String[] test = {"Label", "Accuracy"};
        //test = test + headerList;
        if(chosenClassifier == null){
            completeHeaders = new String[]{Arrays.toString(headerList)};
        } else {
            completeHeaders = new String[]{"Label", "Accuracy", Arrays.toString(headerList)};
        }
        defaultTableModel = new DefaultTableModel(StringUtils.split(Arrays.toString(completeHeaders), ","),0);
        flowTable = new JTable(defaultTableModel);
        flowTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        scrollPane = new JScrollPane(flowTable);
        scrollPane.setBorder(BorderFactory.createEmptyBorder(0,0,0,0));

        pane.add(scrollPane,BorderLayout.CENTER);

        return pane;
    }

    public static String[] getHeaders(){
        return completeHeaders;
    }
    private JPanel initClassifierPane(){
        JPanel btnPane = new JPanel();
        btnPane.setLayout(new BoxLayout(btnPane, BoxLayout.X_AXIS));
        /*btnSave = new JButton("Save as");
        btnGraph = new JButton("Graphs");
        btnSave.setFocusable(false);
        btnSave.setEnabled(false);
        btnGraph.setFocusable(false);
        btnGraph.setEnabled(false);*/
        btnPane.add(classifierLabel);
        setLayout(new BorderLayout(5, 5));
        setBorder(new EmptyBorder(10, 10, 10, 10));
        classifierEle = new Vector<>();
        classifierBox = new JComboBox<>(classifierEle);
        classifierBox.setEditable(true);
        btnPane.add(classifierBox);
        browseClassifiers.addActionListener(actionEvent -> {
            pmmlChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            pmmlChooser.removeChoosableFileFilter(pmmlChooserFilter);
            int action = pmmlChooser.showOpenDialog(FlowMonitorPane.this);
            if (action == JFileChooser.APPROVE_OPTION) {
                chosenClassifier = pmmlChooser.getSelectedFile();
                logger.debug("Real Time classifier {}", chosenClassifier.getPath());
                setComboBox(classifierBox, classifierEle, chosenClassifier);
            }
        });
        btnPane.add(browseClassifiers);
//        add(initCenterPane(), BorderLayout.CENTER);

        pmmlChooser = new JFileChooser(new File(FlowMgr.getInstance().getmDataPath()));
        TextFileFilter pmmlChooserFilter = new TextFileFilter("PMML (*.pmml)", new String[]{"pmml"});
        pmmlChooser.setFileFilter(pmmlChooserFilter);

        /*btnSave.addActionListener(actionEvent -> {
            int action = pmmlChooser.showSaveDialog(FlowMonitorPane.this);
            if (action == JFileChooser.APPROVE_OPTION) {

                File selectedFile = pmmlChooser.getSelectedFile();
                String filename = FilenameUtils.removeExtension(selectedFile.getName());
                if (!FilenameUtils.getExtension(filename).equalsIgnoreCase("csv")) {
                    //save name not okay
                    selectedFile = new File(selectedFile.getParentFile(), FilenameUtils.getBaseName(filename) + ".csv");
                }
                String title = "file conflict";
                String message = "Another file with the same name already exists,do you want to overwrite?";

                if (selectedFile.exists()) {

                    int reply = JOptionPane.showConfirmDialog(this, message, title, JOptionPane.YES_NO_OPTION);

                    if (reply == JOptionPane.YES_OPTION) {
                        JTable2CSVWorker worker = new JTable2CSVWorker(flowTable, selectedFile);
                        worker.execute();
                    } else {
                        btnSave.doClick();
                    }
                } else {
                    JTable2CSVWorker worker = new JTable2CSVWorker(flowTable, selectedFile);
                    worker.execute();
                }
                //File lastSave = selectedFile;
                btnGraph.setEnabled(true);
            }
        });

        //btnGraph.addActionListener(actionEvent -> GuavaMgr.getInstance().getEventBus().post(new FlowVisualEvent(lastSave)));
        btnPane.add(Box.createHorizontalGlue());
        btnPane.add(btnSave);
        btnPane.add(Box.createHorizontalGlue());
        btnPane.add(btnGraph);
        btnPane.add(Box.createHorizontalGlue());
        btnPane.setBorder(BorderFactory.createRaisedSoftBevelBorder());
*/
       // JTable2CSVWorker worker = new JTable2CSVWorker(flowTable, selectedFile);
        //worker.execute();
        return btnPane;
    }

    private JPanel initStatusPane() {
        JPanel pane = new JPanel();
        pane.setLayout(new BoxLayout(pane, BoxLayout.X_AXIS));
        lblStatus = new JLabel("Get ready");
        lblStatus.setForeground(SystemColor.desktop);
        JLabel lblFlowCnt = new JLabel("0");

        pane.add(Box.createHorizontalStrut(5));
        pane.add(lblStatus);
        pane.add(Box.createHorizontalGlue());
        pane.add(lblFlowCnt);
        pane.add(Box.createHorizontalStrut(5));

        return pane;
    }

    private JPanel initNWifsPane() {
        JPanel pane = new JPanel(new BorderLayout(0, 0));
        pane.setBorder(BorderFactory.createLineBorder(new Color(0x555555)));
        pane.add(initNWifsButtonPane(), BorderLayout.WEST);
        pane.add(initNWifsListPane(), BorderLayout.CENTER);

        return pane;
    }

    private JPanel initNWifsButtonPane() {
        JPanel pane = new JPanel();
        pane.setBorder(BorderFactory.createEmptyBorder(10,15,10,15));
        pane.setLayout(new BoxLayout(pane, BoxLayout.Y_AXIS));

        Dimension d = new Dimension(80,48);

        btnLoad = new JButton("Load");
        btnLoad.setMinimumSize(d);
        btnLoad.setMaximumSize(d);
        btnLoad.addActionListener(actionEvent -> loadPcapIfs());

        btnStart = new JToggleButton("Start");
        btnStart.setMinimumSize(d);
        btnStart.setMaximumSize(d);
        btnStart.setEnabled(false);
        btnStart.addActionListener(actionEvent -> startTrafficFlow());

        btnStop = new JToggleButton("Stop");
        btnStop.setMinimumSize(d);
        btnStop.setMaximumSize(d);
        btnStop.setEnabled(false);
        btnStop.addActionListener(actionEvent -> stopTrafficFlow());

        btnGroup = new ButtonGroup();
        btnGroup.add(btnStart);
        btnGroup.add(btnStop);

        pane.add(Box.createVerticalGlue());
        pane.add(btnLoad);
        pane.add(Box.createVerticalGlue());
        pane.add(btnStart);
        pane.add(Box.createVerticalGlue());
        pane.add(btnStop);
        pane.add(Box.createVerticalGlue());

        return pane;
    }

    private JPanel initNWifsListPane() {
        JPanel pane = new JPanel();
        pane.setLayout(new BorderLayout(0, 0));
        pane.setBorder(BorderFactory.createEmptyBorder(0,0,0,0));

        listModel = new DefaultListModel<>();
        listModel.addElement(new PcapIfWrapper("Click Load button to load network interfaces"));
        list = new JList<>(listModel);
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setSelectedIndex(0);
        JScrollPane scrollPane = new JScrollPane(list);
        scrollPane.setBorder(BorderFactory.createEmptyBorder(0,0,0,0));

        pane.add(scrollPane,BorderLayout.CENTER);
        return pane;
    }

    private void loadPcapIfs() {
        LoadPcapInterfaceWorker task = new LoadPcapInterfaceWorker();
        task.addPropertyChangeListener(event -> {
            if ("state".equals(event.getPropertyName())) {
                LoadPcapInterfaceWorker task1 = (LoadPcapInterfaceWorker) event.getSource();
                switch (task1.getState()) {
                    case STARTED:
                        break;
                    case DONE:
                        try {
                            java.util.List<PcapIf> ifs = task1.get();
                            List<PcapIfWrapper> pcapiflist = PcapIfWrapper.fromPcapIf(ifs);

                            listModel.removeAllElements();
                            for(PcapIfWrapper pcapif :pcapiflist) {
                                listModel.addElement(pcapif);
                            }
                            btnStart.setEnabled(true);
                            btnGroup.clearSelection();

                            lblStatus.setText("pick one network interface to listening");
                            lblStatus.validate();

                        } catch (InterruptedException | ExecutionException e) {
                            logger.debug(e.getMessage());
                        }
                        break;
                }
            }
        });
        task.execute();
    }

    private void startTrafficFlow() {
        //Gets name of the selected interface
        String ifName = list.getSelectedValue().name();
        CSVWriter <FlowPrediction> csv_writer;
        if (mWorker != null && !mWorker.isCancelled()) {
            return;
        }
        //Makes filename
//Want to output the Real Time csv to the /data/ directory where it will fall under .gitignore. Although .csv files are already ignored
        /*
        int count = 1;
        while(filename.Exists(){
            addition++;
            filename = LocalDate.now() + "(" + count + ")" + Utils.FLOW_SUFFIX;
        }
        * */
        //String filename = String.valueOf(new File("/data/" + LocalDate.now() + "_" + System.currentTimeMillis() + Utils.FLOW_SUFFIX));
        String filename = LocalDate.now() + "_" + System.currentTimeMillis() + Utils.FLOW_SUFFIX;
        try {
            csv_writer = new CSVWriter<>(filename);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        mWorker = new TrafficFlowWorker(ifName, chosenClassifier, csv_writer);
        mWorker.addPropertyChangeListener(event -> {
            TrafficFlowWorker task = (TrafficFlowWorker) event.getSource();
            if("progress".equals(event.getPropertyName())){
                lblStatus.setText((String) event.getNewValue());
                lblStatus.validate();
            }else if (TrafficFlowWorker.PROPERTY_FLOW.equalsIgnoreCase(event.getPropertyName())) {
                    TrafficFlowWorker.insertFlowFeatures((FlowPrediction) event.getNewValue());
            }else if ("state".equals(event.getPropertyName())) {
                switch (task.getState()) {
                    case STARTED:
                        break;
                    case DONE:
                        try {
                            lblStatus.setText(task.get());
                            lblStatus.validate();
                        } catch(CancellationException e){

                            lblStatus.setText("stop listening");
                            lblStatus.setForeground(SystemColor.GRAY);
                            lblStatus.validate();
                            logger.info("Pcap stop listening");

                        } catch (InterruptedException | ExecutionException e) {
                            logger.debug(e.getMessage());
                        }
                        break;
                }
            }
        });
        mWorker.execute();
        lblStatus.setForeground(SystemColor.desktop);
        btnLoad.setEnabled(false);
        btnStop.setEnabled(true);
    }

    private void stopTrafficFlow() {

        if (mWorker != null) {
            mWorker.cancel(true);
        }

        //FlowMgr.getInstance().stopFetchFlow();
        btnLoad.setEnabled(true);

        String path = FlowMgr.getInstance().getAutoSaveFile();
        logger.info("path:{}", path);

        if(defaultTableModel.getRowCount()>0 && new File(path).exists()) {
            String msg = "The flow has been saved to :" + Utils.LINE_SEP + path;

            UIManager.put("OptionPane.minimumSize",new Dimension(0, 0));
            JOptionPane.showMessageDialog(this.getParent(), msg);
        }
    }

    public static Boolean checkClassifier() {
        return chosenClassifier == null;
    }
}
