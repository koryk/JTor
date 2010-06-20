package org.torproject.jtor.hiddenservice.test;


import static org.junit.Assert.*;

import java.io.File;
import org.torproject.jtor.Tor;
import org.torproject.jtor.TorClient;
import org.torproject.jtor.data.exitpolicy.PortRange;
import org.torproject.jtor.directory.Directory;
import org.torproject.jtor.directory.DirectoryServer;
import org.torproject.jtor.directory.Router;
import org.torproject.jtor.hiddenservice.publishing.HiddenService;
import org.junit.*;
public class TestHiddenService {	
	String privateKey = "-----BEGIN RSA PRIVATE KEY-----\r\nMIICXQIBAAKBgQDRiukvIG8eKFuB8eamrMBv16lTbXFEQyceWaqRgrPjbzb/+wXT\r\nQCSHWZxg8GhkB3aioPcyBpNDPG8kO3Hz52CDwxTX8GGesdfsFNqCfVK1KoY6ryoK\r\nrj7SGoTlmbyQcqzUn0PIW1zFUyufq0NV6SCWMcdDK0evILRaxoG3lPaUYQIDAQAB\r\nAoGBAJ2UbnoPVSEDzpUxWnh7r5gsQd1Ij4Z7Tb7IRbp55VgjOeRVXXMZaJ8U58IK\r\n6SZYaoIwtNU9Fp/YoehIgBChLvVqzmNuIAouHBLsTVzZN1zOY9EVV+Lsvm+ruuw9\r\nN1+12Hd/8jtd3+CzfeBLYNxYg3S2KmpG4+QYJtGhH5YwawrlAkEA9igl74S+3Qsa\r\nx8xPOzW53nO5lS3ZbJy7CHsYG7YflHro4WSZpYdORK+wGzW6Bat2iAW0P2R19szD\r\n32d19GOM6wJBANnr84ly93Q8s8EFfReHiCAuvj4V5G4C3iU/tDIHmX8XkDS6ileN\r\nHb0yJEyEL3NoVuKsoNRomMuaXLDWOatp4OMCQE26A7CMBBCcLwqj0ujpYBWECTe3\r\n0I3hN5XH+KbXbUVfQiXZtEJ2ZRp/N2aAIosjxzvQQUg7Gpyhr7/dVXuj650CQFyL\r\nz8k3gc9jWBNI+W7cp/rC3xgOxAvUO/MlsqjsgUtv/lXmQoob691FRhUYre4dCYkK\r\nNuL96KXO0D5pO+SH+nECQQCi1abLxJUByoXMHe34oSQg1NWuerScSI7yxRUAcfyY\r\n+DXV3faQxTsbTlldvQJMbDsLp/LzB1ZRbxNfHIegbcAS\r\n-----END RSA PRIVATE KEY-----";
	String hostname = "q7dsyayxu45irghj";
	/**
	 * Test the instantiation from configuration directory created by Tor
	 */
	@Test public void testHiddenServiceInstantiationFromConfigDirectory() {
		new TorClient();
		HiddenService hiddenService = HiddenService.createServiceFromDirectory(new File("test/hidden_service_test/"));
	    //private key is read okay
		assertTrue(hiddenService.getPrivateKey().toPEMFormat().trim().equals(privateKey.trim()));
	}
	@Test public void testHiddenServiceHostnameGeneration(){
		HiddenService hiddenService = HiddenService.createServiceFromDirectory(new File("test/hidden_service_test/"));
		assertTrue(hiddenService.getHiddenServiceDescriptor().getOnionAddress().equals(hostname));
	}
}
