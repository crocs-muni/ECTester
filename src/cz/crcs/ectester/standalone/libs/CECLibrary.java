package cz.crcs.ectester.standalone.libs;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class CECLibrary implements ECLibrary {

    private String resourcePath;
    private String libname;

    public CECLibrary(String resourcePath, String libname) {
        this.resourcePath = resourcePath;
        this.libname = libname;
    }

    @Override
    public boolean initialize() {
        // load the library here.
        return false;
    }

    @Override
    public String name() {
        return libname;
    }

    @Override
    public String toString() {
        return name();
    }
}
