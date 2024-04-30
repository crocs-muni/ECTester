package cz.crcs.ectester.standalone.libs.jni;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class SigInfo {

    private final int signo;
    private final int code;
    private final int errno;
    private final int pid;
    private final int uid;
    private final long addr;
    private final int status;
    private final long band;
    private final long sigval;

    public SigInfo(int signo, int code, int errno, int pid, int uid, long addr, int status, long band, long sigval) {
        this.signo = signo;
        this.code = code;
        this.errno = errno;
        this.pid = pid;
        this.uid = uid;
        this.addr = addr;
        this.status = status;
        this.band = band;
        this.sigval = sigval;
    }

    public int getSigno() {
        return signo;
    }

    public int getCode() {
        return code;
    }

    public int getErrno() {
        return errno;
    }

    public int getPid() {
        return pid;
    }

    public int getUid() {
        return uid;
    }

    public long getAddr() {
        return addr;
    }

    public int getStatus() {
        return status;
    }

    public long getBand() {
        return band;
    }

    public long getSigval() {
        return sigval;
    }

    @Override
    public String toString() {
        return "SigInfo{" +
                "signo=" + signo +
                ", code=" + code +
                ", errno=" + errno +
                ", pid=" + pid +
                ", uid=" + uid +
                ", addr=" + addr +
                ", status=" + status +
                ", band=" + band +
                ", sigval=" + sigval +
                '}';
    }
}
