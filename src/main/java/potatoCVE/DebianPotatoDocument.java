package potatoCVE;

import com.google.common.base.CharMatcher;
import com.google.common.base.Objects;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.util.*;

public class DebianPotatoDocument extends HashSet<DebianPotatoDocument.CVEInformation> {
    DebianPotatoDocument(String filename) throws ParserConfigurationException, IOException, SAXException, DOMException {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

        factory.setValidating(false);
        factory.setNamespaceAware(false);

        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new File(filename));

        Element root = doc.getDocumentElement(),
                defsElem = null,
                testsElem = null,
                objectsElem = null,
                statesElem = null;
        NodeList childNodes = root.getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node n = childNodes.item(i);
            if (n instanceof Element) {
                Element e = (Element) n;
                String name = e.getTagName();
                if (name.equals("definitions"))
                    defsElem = e;
                else if (name.equals("tests"))
                    testsElem = e;
                else if (name.equals("objects"))
                    objectsElem = e;
                else if (name.equals("states"))
                    statesElem = e;
            }
        }

        if (defsElem == null ||
                testsElem == null ||
                objectsElem == null ||
                statesElem == null) {
            throw new RuntimeException("Missing elements in XML file");
        }

        final LinkedHashMap<String, String> versions, packages;
        packages = loadPackages(objectsElem);
        versions = loadVersions(statesElem);

        final LinkedHashMap<String, VersionInformation> tests;
        tests = loadTests(testsElem, packages, versions);

        this.loadDefinitions(defsElem, tests);
    }

    static private LinkedHashMap<String, String> loadPackages(Element objectsElem) {
        LinkedHashMap<String, String> result = new LinkedHashMap<String, String>();
        NodeList objects = objectsElem.getChildNodes();
        NodeList packages = objectsElem.getElementsByTagName("dpkginfo_object");
        for (int i = 0; i < packages.getLength(); i++) {
            Element e = (Element) packages.item(i);
            String id = e.getAttribute("id");
            String text = CharMatcher.WHITESPACE.trimFrom(e.getTextContent());
            result.put(id, text);
        }
        return result;
    }

    static private LinkedHashMap<String, String> loadVersions(Element statesElem) {
        LinkedHashMap<String, String> result = new LinkedHashMap<String, String>();
        NodeList versions = statesElem.getElementsByTagName("dpkginfo_state");
        for (int i = 0; i < versions.getLength(); i++) {
            Element state = (Element) versions.item(i);
            String id = state.getAttribute("id");
            String text = CharMatcher.WHITESPACE.trimFrom(state.getTextContent());
            result.put(id, text);
        }
        return result;
    }

    static private LinkedHashMap<String, VersionInformation> loadTests(
            Element testsElem,
            Map<String, String> packages,
            Map<String, String> versions) {
        LinkedHashMap<String, VersionInformation> result =
                new LinkedHashMap<String, VersionInformation>();
        NodeList tests = testsElem.getElementsByTagName("dpkginfo_test");
        for (int i = 0; i < tests.getLength(); i++) {
            Element test = (Element) tests.item(i);
            String id = test.getAttribute("id");
            String object_id = ((Element) test.getElementsByTagName("object").item(0)).getAttribute("object_ref");
            String state_id = ((Element) test.getElementsByTagName("state").item(0)).getAttribute("state_ref");
            result.put(id, new VersionInformation(packages.get(object_id), versions.get(state_id)));
        }
        return result;
    }

    private void loadDefinitions(Element defElement, Map<String, VersionInformation> tests) {
        NodeList defs = defElement.getElementsByTagName("definition");
        for (int i = 0; i < defs.getLength(); i++) {
            Element def = (Element) defs.item(i);
            if (!def.getAttribute("class").equals("vulnerability"))
                continue;

            String id = def.getAttribute("id");

            ArrayList<String> cves = new ArrayList<String>();
            NodeList refs = def.getElementsByTagName("reference");
            for (int j = 0; j < refs.getLength(); j++) {
                Element ref = (Element) refs.item(j);
                String ref_id = ref.getAttribute("ref_id");
                if (ref_id.matches("CVE-[0-9-]+")) {
                    cves.add(ref_id);
                }
            }

            Set<VersionInformation> constraints = new HashSet<VersionInformation>();
            NodeList criteria = def.getElementsByTagName("criterion");
            for (int j = 0; j < criteria.getLength(); j++) {
                Element criterion = (Element) criteria.item(j);
                if (!criterion.hasAttribute("test_ref"))
                    continue;
                String test_ref = criterion.getAttribute("test_ref");
                if (!tests.containsKey(test_ref))
                    continue;
                constraints.add(tests.get(test_ref));
            }

            this.add(new CVEInformation(id, cves, constraints));
        }
    }

    static class VersionInformation {
        final String name;
        final String version;

        VersionInformation(String name, String version) {
            this.name = name;
            this.version = version;
        }

        public String toString() {
            return Objects.toStringHelper(this)
                    .add("name", name)
                    .add("version", version)
                    .toString();
        }

        public String getName() {
            return name;
        }

        public String getVersion() {
            return version;
        }
    }

    public static class CVEInformation {
        String id;
        ArrayList<String> cves;
        Set<VersionInformation> constraints;

        CVEInformation(String id, ArrayList<String> cves, Set<VersionInformation> constraints) {
            this.id = id;
            this.cves = cves;
            this.constraints = constraints;
        }

        public String toString() {
            return Objects.toStringHelper(this)
                    .add("id", id)
                    .add("CVEs", cves)
                    .add("constraints", constraints)
                    .toString();
        }

        public String getId() {
            return id;
        }

        public ArrayList<String> getCves() {
            return cves;
        }

        public Set<VersionInformation> getConstraints() {
            return constraints;
        }
    }
}
