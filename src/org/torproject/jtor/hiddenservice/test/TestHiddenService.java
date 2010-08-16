package org.torproject.jtor.hiddenservice.test;


import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.StringBufferInputStream;

import org.torproject.jtor.TorClient;
import org.torproject.jtor.circuits.impl.CircuitManagerImpl;
import org.torproject.jtor.crypto.TorPrivateKey;
import org.torproject.jtor.data.exitpolicy.PortRange;
import org.torproject.jtor.directory.Directory;
import org.torproject.jtor.directory.DirectoryServer;
import org.torproject.jtor.directory.Router;
import org.torproject.jtor.hiddenservice.HiddenServiceDescriptor;
import org.torproject.jtor.hiddenservice.HiddenServiceDescriptorParser;
import org.torproject.jtor.hiddenservice.publishing.HiddenService;
import org.torproject.jtor.logging.Logger;
import org.junit.*;

import com.sun.xml.internal.ws.api.wsdl.parser.ServiceDescriptor;

public class TestHiddenService {	
	String privateKey = "-----BEGIN RSA PRIVATE KEY-----\r\nMIICXQIBAAKBgQDRiukvIG8eKFuB8eamrMBv16lTbXFEQyceWaqRgrPjbzb/+wXT\nQCSHWZxg8GhkB3aioPcyBpNDPG8kO3Hz52CDwxTX8GGesdfsFNqCfVK1KoY6ryoK\nrj7SGoTlmbyQcqzUn0PIW1zFUyufq0NV6SCWMcdDK0evILRaxoG3lPaUYQIDAQAB\nAoGBAJ2UbnoPVSEDzpUxWnh7r5gsQd1Ij4Z7Tb7IRbp55VgjOeRVXXMZaJ8U58IK\n6SZYaoIwtNU9Fp/YoehIgBChLvVqzmNuIAouHBLsTVzZN1zOY9EVV+Lsvm+ruuw9\nN1+12Hd/8jtd3+CzfeBLYNxYg3S2KmpG4+QYJtGhH5YwawrlAkEA9igl74S+3Qsa\nx8xPOzW53nO5lS3ZbJy7CHsYG7YflHro4WSZpYdORK+wGzW6Bat2iAW0P2R19szD\n32d19GOM6wJBANnr84ly93Q8s8EFfReHiCAuvj4V5G4C3iU/tDIHmX8XkDS6ileN\nHb0yJEyEL3NoVuKsoNRomMuaXLDWOatp4OMCQE26A7CMBBCcLwqj0ujpYBWECTe3\n0I3hN5XH+KbXbUVfQiXZtEJ2ZRp/N2aAIosjxzvQQUg7Gpyhr7/dVXuj650CQFyL\nz8k3gc9jWBNI+W7cp/rC3xgOxAvUO/MlsqjsgUtv/lXmQoob691FRhUYre4dCYkK\nNuL96KXO0D5pO+SH+nECQQCi1abLxJUByoXMHe34oSQg1NWuerScSI7yxRUAcfyY\n+DXV3faQxTsbTlldvQJMbDsLp/LzB1ZRbxNfHIegbcAS\n-----END RSA PRIVATE KEY-----";
	String hostname = "q7dsyayxu45irghj";
	public static Logger logger = null;
	private static TorClient tc = new TorClient();

	@Test public void testInstantiation() {
		tc.start();
		logger = tc.logManager.getLogger("hidden-services");
		logger.enableDebug();
		logger.debug("Hidden services test started");
		assertTrue(logger != null);		
	}
	/**
	 * Tests the instantiation from configuration directory created by Tor
	 * and if the key is rendered correctly.
	 */
	@Test public void testHiddenServiceInstantiationFromConfigDirectory() {

		HiddenService hiddenService = HiddenService.createServiceFromDirectory(new File("test/hidden_service_test/"), logger);
	    //private key is read okay
		TorPrivateKey locKey = TorPrivateKey.createFromPEMBuffer(privateKey);

		logger.debug("Testing hidden service instantiation from directory.");
		assertTrue(hiddenService.getPrivateKey().getFingerPrint().toString().equals(locKey.getFingerPrint().toString()));
	}
	@Test public void testV2Parser(){
		HiddenService hiddenService = new HiddenService("JTor test service", PortRange.createFromString("80-80"), TorPrivateKey.createFromPEMBuffer(privateKey), logger);
		//HiddenServiceDescriptor hsd = HiddenServiceDescriptor.fetchServiceDescriptor(hostname, tc.directory, tc.circuitManager, logger);
		//hiddenService.writeDescriptorToFile(new File("./test/test_descriptor"));
		HiddenServiceDescriptorParser hsp = new HiddenServiceDescriptorParser(new ByteArrayInputStream(hiddenService.getHiddenServiceDescriptor().getDescriptorString().getBytes()), logger);
		assertTrue(hsp.isVerified());         
	}
	@Test public void testTimePeriodGeneration(){
		float sampleTime = 1188241957;
		float descriptorByte = 143;
		int timePeriod = (int)((sampleTime + (descriptorByte * 337.5)) / 86400);
		assertTrue (timePeriod == 13753);
	}	
	/**
	 * Tests the generation of the onion address.
	 */
	@Test public void testHiddenServiceHostnameGeneration(){
		HiddenService hiddenService = HiddenService.createServiceFromDirectory(new File("test/hidden_service_test/"), logger);
		assertTrue(hiddenService.getHiddenServiceDescriptor().getOnionAddress().equals(hostname));
	}	
	@Test public void testHiddenServiceDescriptorPublishing(){

        HiddenService hiddenService = new HiddenService("JTor test service", PortRange.createFromString("80-80"), TorPrivateKey.createFromPEMBuffer(privateKey), logger);
		hiddenService.generateServiceDescriptor();
		
		assertTrue(hiddenService.advertiseDescriptor(tc.directory));
	}
	/**
	 * Tests the fetching of hidden service v2 descriptor
	 * Finds a group of 6 random hidden service directories
	 * Sends get request to a random directory until successful
	 */
	@Test public void testHiddenServiceDescriptorFetching(){

		HiddenServiceDescriptor hsd = HiddenServiceDescriptor.fetchServiceDescriptor(hostname, tc.directory, tc.circuitManager, logger);
		assertTrue(hsd != null);
	}
	
	/** 
	 * Tests the generation of the secret id
	 */
	@Test public void testSecretIDGeneration(){
		
	}

	/**
	 * Tests the generation of the descriptor id
	 */
	@Test public void testDescriptorIDGeneration(){
		
	}

	
}
