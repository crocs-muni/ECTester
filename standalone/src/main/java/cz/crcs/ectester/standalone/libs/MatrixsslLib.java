package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class MatrixsslLib extends NativeECLibrary {

    public MatrixsslLib() {
        super("matrixssl_provider");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();
}
