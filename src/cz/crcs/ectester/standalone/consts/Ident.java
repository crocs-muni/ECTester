package cz.crcs.ectester.standalone.consts;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.*;
import java.util.function.BiFunction;

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

    public boolean containsAny(List<String> others) {
        for(String other : others) {
            if(name.equals(other) || idents.contains(other)) {
                return true;
            }
        }
        return false;
    }

    <T> T getInstance(BiFunction<String, Provider, T> getter, Provider provider) throws NoSuchAlgorithmException {
        T instance = null;
        try {
            instance = getter.apply(name, provider);
        } catch (Exception ignored) {
            ignored.printStackTrace();
        }

        if (instance == null) {
            for (String alias : idents) {
                try {
                    instance = getter.apply(alias, provider);
                    if (instance != null) {
                        break;
                    }
                } catch (Exception ignored) {
                    ignored.printStackTrace();
                }
            }
        }

        if (instance == null) {
            throw new NoSuchAlgorithmException(name);
        }
        return instance;
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
        return "(" + String.join(" | ", idents) + ")";
    }
}
