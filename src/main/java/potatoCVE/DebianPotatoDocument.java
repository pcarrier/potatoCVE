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

    static private LinkedHashMap<String, String> loadPackages(final Element objectsElem) {
        final LinkedHashMap<String, String> result = new LinkedHashMap<String, String>();
        final NodeList objects = objectsElem.getChildNodes();
        final NodeList packages = objectsElem.getElementsByTagName("dpkginfo_object");
        for (int i = 0; i < packages.getLength(); i++) {
            final Element e = (Element) packages.item(i);
            final String id = e.getAttribute("id");
            final String text = CharMatcher.WHITESPACE.trimFrom(e.getTextContent());
            result.put(id, text);
        }
        return result;
    }

    static private LinkedHashMap<String, String> loadVersions(final Element statesElem) {
        final LinkedHashMap<String, String> result = new LinkedHashMap<String, String>();
        final NodeList versions = statesElem.getElementsByTagName("dpkginfo_state");
        for (int i = 0; i < versions.getLength(); i++) {
            final Element state = (Element) versions.item(i);
            final String id = state.getAttribute("id");
            final String text = CharMatcher.WHITESPACE.trimFrom(state.getTextContent());
            result.put(id, text);
        }
        return result;
    }

    static private LinkedHashMap<String, VersionInformation> loadTests(
            final Element testsElem,
            final Map<String, String> packages,
            final Map<String, String> versions) {
        LinkedHashMap<String, VersionInformation> result =
                new LinkedHashMap<String, VersionInformation>();
        final NodeList tests = testsElem.getElementsByTagName("dpkginfo_test");
        for (int i = 0; i < tests.getLength(); i++) {
            final Element test = (Element) tests.item(i);
            final String id = test.getAttribute("id");
            final String object_id = ((Element) test.getElementsByTagName("object").item(0)).getAttribute("object_ref");
            final String state_id = ((Element) test.getElementsByTagName("state").item(0)).getAttribute("state_ref");
            result.put(id, new VersionInformation(packages.get(object_id), versions.get(state_id)));
        }
        return result;
    }

    private void loadDefinitions(final Element defElement, final Map<String, VersionInformation> tests) {
        final NodeList defs = defElement.getElementsByTagName("definition");
        for (int i = 0; i < defs.getLength(); i++) {
            final Element def = (Element) defs.item(i);
            if (!def.getAttribute("class").equals("vulnerability"))
                continue;

            final String id = def.getAttribute("id");

            final ArrayList<String> cves = new ArrayList<String>();
            final NodeList refs = def.getElementsByTagName("reference");
            for (int j = 0; j < refs.getLength(); j++) {
                final Element ref = (Element) refs.item(j);
                final String ref_id = ref.getAttribute("ref_id");
                if (ref_id.matches("CVE-[0-9-]+")) {
                    cves.add(ref_id);
                }
            }

            Set<VersionInformation> constraints = new HashSet<VersionInformation>();
            final NodeList criteria = def.getElementsByTagName("criterion");
            for (int j = 0; j < criteria.getLength(); j++) {
                final Element criterion = (Element) criteria.item(j);
                if (!criterion.hasAttribute("test_ref"))
                    continue;
                final String test_ref = criterion.getAttribute("test_ref");
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

        VersionInformation(final String name, final String version) {
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
        final String id;
        final ArrayList<String> cves;
        final Set<VersionInformation> constraints;

        CVEInformation(final String id, final ArrayList<String> cves, final Set<VersionInformation> constraints) {
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
