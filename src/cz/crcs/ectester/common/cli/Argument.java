package cz.crcs.ectester.common.cli;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class Argument {
    private String name;
    private String desc;
    private boolean required;

    public Argument(String name, String desc, boolean isRequired) {
        this.name = name;
        this.desc = desc;
        this.required = isRequired;
    }


    public String getName() {
        return name;
    }

    public String getDesc() {
        return desc;
    }

    public boolean isRequired() {
        return required;
    }
}
