package potatoCVE;

import org.codehaus.jackson.map.ObjectMapper;

public class CLI {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("I take a Debian CVE filename as an argument.");
            System.exit(1);
        }
        DebianPotatoDocument potato = new DebianPotatoDocument(args[0]);

        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(System.out, potato);
    }
}
