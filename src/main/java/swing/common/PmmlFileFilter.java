package swing.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.filechooser.FileFilter;
import java.io.File;

public class PmmlFileFilter extends FileFilter {
    protected static final Logger logger = LoggerFactory.getLogger(PmmlFileFilter.class);

    @Override
    public boolean accept(File file) {

        if (file.isDirectory()) {
            return true;
        }else {
            return SwingUtils.isPmmlFile(file);
        }
    }

    @Override
    public String getDescription() {
        return "PMML file (*.pmml)";
    }
}
