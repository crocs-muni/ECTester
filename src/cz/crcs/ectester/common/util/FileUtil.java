package cz.crcs.ectester.common.util;

import cz.crcs.ectester.common.output.TeeOutputStream;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class FileUtil {
    public static OutputStream openStream(String[] files) throws FileNotFoundException {
        if (files == null) {
            return null;
        }
        List<OutputStream> outs = new LinkedList<>();
        for (String fileOut : files) {
            outs.add(new FileOutputStream(fileOut));
        }
        return new TeeOutputStream(outs.toArray(new OutputStream[0]));
    }

    public static OutputStreamWriter openFiles(String[] files) throws FileNotFoundException {
        if (files == null) {
            return null;
        }
        return new OutputStreamWriter(openStream(files));
    }
}
