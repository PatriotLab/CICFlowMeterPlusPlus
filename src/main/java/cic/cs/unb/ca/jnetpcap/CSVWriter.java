package cic.cs.unb.ca.jnetpcap;

import cic.cs.unb.ca.jnetpcap.features.FeatureCollection;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.FileWriter;
import java.io.IOException;

public final class CSVWriter<T extends FeatureCollection> implements java.io.Closeable {
    private final CSVPrinter printer;
    private Boolean has_header = false;

    public CSVWriter(String filename) throws IOException {
        printer = new CSVPrinter(new FileWriter(filename), CSVFormat.RFC4180);
    }

    public void write(T flow) throws IOException {
        if(!has_header){
            printer.printRecord((Object[])flow.getHeader());
            has_header = true;
        }
        printer.printRecord((Object[])flow.getData());
    }

    public Runnable writeFuture(T flow){
        return new InsertRow<T>(this, flow);
    }

    @Override
    public void close() throws IOException {
        printer.close(true);
    }

    static class InsertRow<T extends FeatureCollection> implements Runnable {
        CSVWriter<T> writer;
        T flow;

        InsertRow(CSVWriter<T> writer, T flow){
            this.writer = writer;
            this.flow = flow;
        }

        @Override
        public void run() {
            try {
                writer.write(flow);
            } catch (IOException e) {
                throw new RuntimeException("Error writing row to csv", e);
            }
        }
    }
}
