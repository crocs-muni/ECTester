package cz.crcs.ectester.standalone.consts;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

public abstract class Ident {
    Set<String> idents;
    String name;

    public Ident(String name, String... aliases) {
        this.name = name;
        this.idents = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        this.idents.add(name);
        this.idents.addAll(Arrays.asList(aliases));
    }

    public String getName() {
        return name;
    }

    public Set<String> getIdents() {
        return Collections.unmodifiableSet(idents);
    }

    public boolean contains(String other) {
        return name.equals(other) || idents.contains(other);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Ident)) {
            return false;
        }
        Ident other = (Ident) obj;
        return idents.equals(other.getIdents());
    }

    @Override
    public int hashCode() {
        return idents.hashCode() + 37;
    }

    @Override
    public String toString() {
        return "(" + String.join("|", idents) + ")";
    }
}
