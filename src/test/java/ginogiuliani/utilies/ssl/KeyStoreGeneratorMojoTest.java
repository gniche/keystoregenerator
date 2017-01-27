package ginogiuliani.utilies.ssl;

import junit.framework.TestCase;
import org.apache.maven.model.Resource;
import org.apache.maven.project.MavenProject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.when;

public class KeyStoreGeneratorMojoTest extends TestCase {

    KeyStoreGeneratorMojo sut = new KeyStoreGeneratorMojo();

    @Mock
    private MavenProject mavenProject;

    private static final List<Resource> resources = new ArrayList<>();
    private static final String RESOURCES_FOLDER = "./.";
    private static final String OUTPUT_FILE_PATH = getOutputFilePath();
    private static final String CERT_FOLDER_PATH = "certificates";
    private static final String KEYSTORE_PATH_NAME = "keystore.jks";
    private static String CERTIFICATE_NAME = "gbgCertificate.crt";
    private static String KEYSTORE_PASSWORD = "password";

    @Before
    public void setUp() throws IOException {
        MockitoAnnotations.initMocks(this);
        sut.project = mavenProject;
        sut.outputDirectory = new File(OUTPUT_FILE_PATH);
        sut.keystoreFilePath = KEYSTORE_PATH_NAME;
        sut.certificatesFilePath = CERT_FOLDER_PATH;
        sut.keyStorePassword = KEYSTORE_PASSWORD;
        Resource resource = new Resource();
        resource.setDirectory(OUTPUT_FILE_PATH);
        resources.add(resource);
        when(mavenProject.getResources()).thenReturn(resources);
    }


    @Test
    public void test_generate_keystore() throws Exception {
        sut.execute();
        String path = OUTPUT_FILE_PATH + KEYSTORE_PATH_NAME;
        System.out.println(path);
        File file = new File(path);
        Assert.assertTrue(file.exists());
        X509TrustManager trustManager = getTrustManager(getKeyStore(file));
        String certificateTestPath = OUTPUT_FILE_PATH + CERT_FOLDER_PATH + "\\" + CERTIFICATE_NAME;
        X509Certificate cert = sut.convertTextToX509Certificate(new File(certificateTestPath));
        Assert.assertEquals(1, trustManager.getAcceptedIssuers().length);
        try {
            trustManager.checkClientTrusted(new X509Certificate[]{cert}, "RSA");
            trustManager.checkServerTrusted(new X509Certificate[]{cert}, "RSA");
        } catch (CertificateException e) {
            fail("Test certificate not trusted");
        }
    }

    @Test
    public void test_fileWithoutCert_doesNotCreate_X5009Certificate() throws Exception {
        File testCertificateFile = new File(OUTPUT_FILE_PATH + CERT_FOLDER_PATH + "\\" + "blah.crt");
        Assert.assertTrue(testCertificateFile.exists());
        X509Certificate cert = sut.convertTextToX509Certificate(testCertificateFile);
        Assert.assertNull(cert);
    }

    private static X509TrustManager getTrustManager(KeyStore keystore) throws Exception {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(keystore);
        return (X509TrustManager) factory.getTrustManagers()[0];
    }

    public static KeyStore getKeyStore(File file) {
        KeyStore keyStore = null;
        try (InputStream inStream = new FileInputStream(file)) {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(inStream, KEYSTORE_PASSWORD.toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return keyStore;
    }

    private static String getOutputFilePath() {
        URL resFolder = KeyStoreGeneratorMojoTest.class.getClassLoader().getResource(RESOURCES_FOLDER);
        String path = resFolder.getFile().substring(1);
        System.out.println(path);
        return path;
    }
}