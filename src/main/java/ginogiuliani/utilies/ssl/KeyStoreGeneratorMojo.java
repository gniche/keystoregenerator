package ginogiuliani.utilies.ssl;

import org.apache.maven.model.Resource;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * @goal generate
 * Mojo which generates keystore
 */
@Mojo(name = "generate")
public class KeyStoreGeneratorMojo extends AbstractMojo {

    /**
     * The maven project which is being used
     */
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    protected MavenProject project;

    /**
     * The output directory into which to copy the resources.
     */
    @Parameter(defaultValue = "${project.build.outputDirectory}", required = true)
    protected File outputDirectory;

    /**
     * The output file path for the keystore, the file name and relative path in the resources folder
     */
    @Parameter(property = "generate.keystoreFilePath", defaultValue = "gbg-public-keystore.jks")
    protected String keystoreFilePath;

    /**
     * The file path for the certificates folder, the file name and relative path in the resources folder
     */
    @Parameter(property = "generate.certificatesFilePath", defaultValue = "\\certificates")
    protected String certificatesFilePath;

    /**
     * Alias prefix for certificates in keystore
     */
    @Parameter(property = "generate.aliasPrefix", defaultValue = "SSL_KEY")
    protected String aliasPrefix;

    /**
     * keystore password
     */
    @Parameter(property = "generate.password", defaultValue = "")
    protected String keyStorePassword;

    CertificateFactory x509certificateFactory;

    private List<Resource> resources;

    public KeyStoreGeneratorMojo() {
        try {
            x509certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            getLog().error(e.getMessage());
        }

    }

    @Override
    public void execute() {
        if (x509certificateFactory == null) {
            return;
        }
        try {
            resources = project.getResources();
            getLog().info("Generating KeyStore");
            generateKeyStore();
            getLog().info("Finished Generating KeyStore");
        } catch (Exception e) {
            getLog().error(e.getMessage());
        }
    }

    private void generateKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] password = keyStorePassword.toCharArray();
        keyStore.load(null, password);

        importAllCerificatesToKeyStore(keyStore);
        writeKeyStoreToFile(keyStore, password);
    }

    private void writeKeyStoreToFile(KeyStore keyStore, char[] password) throws Exception {
        File keyStoreFile = new File(outputDirectory + "\\" + keystoreFilePath);
        getLog().info("Writing keystore to " + keyStoreFile);
        keyStoreFile.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(keyStoreFile.toString())) {
            keyStore.store(fos, password);
        }
    }

    private void importAllCerificatesToKeyStore(KeyStore keyStore) throws KeyStoreException {
        getLog().info("Importing Certificates");

        for (Resource resource : resources) {
            String certificateFolder = resource.getDirectory() + certificatesFilePath;
            File certFolder = new File(certificateFolder);
            File[] files = certFolder.listFiles();
            if (files != null) {
                getLog().info("Certificate resource folder found at: " + certificateFolder);
                for (int i = 0; i < files.length; i++) {
                    X509Certificate certificate = convertTextToX509Certificate(files[i]);
                    if (certificate != null) {
                        String alias = aliasPrefix + "_" + i;
                        getLog().info("Adding Certificate: " + alias);
                        keyStore.setCertificateEntry(alias, certificate);
                    }
                }
            } else {
                getLog().error("Certificate resource folder does not exist: " + certificateFolder);
            }
        }
        getLog().info("Finished importing certificates");
    }

    X509Certificate convertTextToX509Certificate(File file) {
        X509Certificate x509 = null;
        try (InputStream inStream = new FileInputStream(file)) {
            x509 = (X509Certificate) x509certificateFactory.generateCertificate(inStream);
        } catch (IOException | CertificateException e) {
            getLog().error(e.getMessage() + " " + file);
        }
        return x509;
    }
}
