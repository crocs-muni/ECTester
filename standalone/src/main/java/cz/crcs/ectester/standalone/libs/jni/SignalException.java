package cz.crcs.ectester.standalone.libs.jni;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class SignalException extends RuntimeException {

    private final SigInfo sigInfo;

    public SignalException(SigInfo sigInfo) {
        super("Signal caught.");
        this.sigInfo = sigInfo;
    }

    public SigInfo getSigInfo() {
        return sigInfo;
    }
}
