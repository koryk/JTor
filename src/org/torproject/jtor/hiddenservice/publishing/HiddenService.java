package org.torproject.jtor.hiddenservice.publishing;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.torproject.jtor.TorException;
import org.torproject.jtor.circuits.Circuit;
import org.torproject.jtor.circuits.CircuitBuildHandler;
import org.torproject.jtor.circuits.CircuitManager;
import org.torproject.jtor.circuits.CircuitNode;
import org.torproject.jtor.circuits.Connection;
import org.torproject.jtor.circuits.OpenStreamResponse;
import org.torproject.jtor.circuits.impl.CellImpl;
import org.torproject.jtor.circuits.impl.CircuitImpl;
import org.torproject.jtor.circuits.impl.CircuitManagerImpl;
import org.torproject.jtor.circuits.impl.CircuitNodeImpl;
import org.torproject.jtor.circuits.impl.NodeChoiceConstraints;
import org.torproject.jtor.circuits.impl.NodeChooser;
import org.torproject.jtor.circuits.impl.OpenStreamResponseImpl;
import org.torproject.jtor.circuits.impl.StreamExitRequest;
import org.torproject.jtor.crypto.TorPrivateKey;
import org.torproject.jtor.crypto.TorPublicKey;
import org.torproject.jtor.crypto.TorRandom;
import org.torproject.jtor.data.HexDigest;
import org.torproject.jtor.data.IPv4Address;
import org.torproject.jtor.data.exitpolicy.PortRange;
import org.torproject.jtor.directory.Directory;
import org.torproject.jtor.directory.DirectoryServer;
import org.torproject.jtor.directory.Router;
import org.torproject.jtor.directory.impl.DirectoryImpl;
import org.torproject.jtor.directory.impl.RouterImpl;
import org.torproject.jtor.hiddenservice.HiddenServiceCell;
import org.torproject.jtor.hiddenservice.HiddenServiceCellImpl;
import org.torproject.jtor.hiddenservice.HiddenServiceDescriptor;
import org.torproject.jtor.hiddenservice.RendezvousPoint;
import org.torproject.jtor.logging.Logger;

import com.sun.corba.se.impl.ior.ByteBuffer;

// TODO: Auto-generated Javadoc
/**
 * The Class HiddenService.
 */
public class HiddenService {
	
	/** The introduction points. */
	private ArrayList<Router> introductionPoints = new ArrayList<Router>();
	
	/** The hidden service descriptor. */
	private HiddenServiceDescriptor hiddenServiceDescriptor;
	
	/** The private key. */
	private TorPrivateKey privateKey;
	
	public TorPrivateKey getPrivateKey() {
		return privateKey;
	}
	/** The service name. */
	private String serviceName;
	
	private Hashtable<Integer, IntroductionPoint> introCircuits = new Hashtable<Integer, IntroductionPoint>();
; 
	
	/** The service ports. */
	private PortRange servicePorts;
	
	/** the host name .onion address */
	private String hostname;
	
	private Directory directory;
	
	private Logger logger;
	
	public HiddenService(String serviceName, PortRange servicePorts, TorPrivateKey key, Logger logger){
		this.serviceName = serviceName;
		this.servicePorts = servicePorts;
		this.privateKey = key;
		this.logger = logger;
		generateServiceDescriptor();
	}	
	public HiddenService(TorPrivateKey key, Logger logger){
		this.privateKey = key;
		this.logger = logger;
		generateServiceDescriptor();
		//fetch config information
	}
	
	/**
	 * Instantiates a brand new hidden service.
	 * 
	 * @param serviceName
	 *            the service name
	 * @param servicePorts
	 *            the service's ports
	 */
	public HiddenService(String serviceName, PortRange servicePorts, Directory directory, Logger logger) {
		this.serviceName = serviceName;
		this.servicePorts = servicePorts;
		this.directory = directory;
		this.logger = logger;
		generateKeyPair();
		generateServiceDescriptor();
	}
	
	/*
	 * RELAY_COMMAND_ESTABLISH_INTRO cell as defined in 1.2 of rend-spec
	 * 
	 */
	public void sendEstablishIntroCell(CircuitNodeImpl circuitNode, CircuitImpl circ, TorPublicKey keyForIntro){
		HiddenServiceCell cell = HiddenServiceCellImpl.createCell(HiddenServiceCell.RELAY_COMMAND_ESTABLISH_INTRO, circ.getCircuitId());
		cell.putInt(128);
		cell.putByteArray(keyForIntro.toASN1Raw());
		byte[] dh = circuitNode.getContext().getPublicValue().toByteArray();
		byte[] introbytes = "INTRODUCE".getBytes(); 
		byte[] hsbytes = new byte[dh.length + introbytes.length];
		System.arraycopy(hsbytes, 0, dh, 0, dh.length);
		System.arraycopy(hsbytes, dh.length, introbytes, 0, introbytes.length);
		cell.putByteArray(HexDigest.createDigestForData(hsbytes).getRawBytes());
		byte[] allbytes = cell.getCellBytes();
		allbytes = HexDigest.createDigestForData(allbytes).getRawBytes();
		cell.putByteArray(encrypt(allbytes,keyForIntro.getRSAPublicKey()));
		CellImpl newCell = CellImpl.createVarCell(circ.getCircuitId(), HiddenServiceCell.RELAY_COMMAND_ESTABLISH_INTRO, cell.getCellBytes().length);
		circ.sendCell(cell);
	}
	//v1
	public void sendRelayIntroduce1V(CircuitNodeImpl circuitNode, CircuitImpl circ, TorPublicKey hsKey, int authType, byte[] authData, RendezvousPoint rend){
		HiddenServiceCell cell = HiddenServiceCellImpl.createCell(HiddenServiceCell.RELAY_COMMAND_INTRODUCE1V, circ.getCircuitId());
		cell.putInt(1);
		byte[] keyID = new byte[20];
		System.arraycopy(keyID, 0, hsKey.getFingerprint().getRawBytes(), 0, keyID.length);
		cell.putByteArray(keyID);
		cell.putByte(authType);
		if (authType != 0){
			cell.putInt(authData.length);
			cell.putByteArray(authData);
		}
		byte[] cellData = getCommandIntroduce2(circuitNode, circ, hsKey, authType, authData, rend);
		cell.putByteArray(encrypt(cellData,hsKey.getRSAPublicKey()));
	}
	//v3 protocol
	public void sendRelayIntroduce1(CircuitNodeImpl circuitNode, CircuitImpl circ, TorPublicKey hsKey, int authType, byte[] authData, RendezvousPoint rend){
		HiddenServiceCell cell = HiddenServiceCellImpl.createCell(HiddenServiceCell.RELAY_COMMAND_INTRODUCE1, circ.getCircuitId());
		byte[] keyID = new byte[20];
		System.arraycopy(keyID, 0, hsKey.getFingerprint().getRawBytes(), 0, keyID.length);
		cell.putByteArray(keyID);
		ByteBuffer dataBuffer = new ByteBuffer();			
		dataBuffer.append(3);
		dataBuffer.append(authType);
		if (authType != 0){
			dataBuffer.append(authData.length);
			for (byte b : authData)
				dataBuffer.append(b);					
		}
		long currentTime = (new Date()).getTime();
		dataBuffer.append((int)((currentTime + (((int)keyID[0]) * 337.5)) / 86400));
		dataBuffer.append(rend.getAddress().getAddressData());
		dataBuffer.append(rend.getDirectoryPort());
		for (byte b: rend.getIdentityHash().getRawBytes())
			dataBuffer.append(b);
		dataBuffer.append(128);
		for (byte b : rend.getOnionKey().toASN1Raw())
			dataBuffer.append(b);
		for (byte b : rend.getRendezvousCookie())
			dataBuffer.append(b);
		for (byte b : circuitNode.getContext().getPublicKeyBytes())
			dataBuffer.append(b);
		cell.putByteArray(encrypt(dataBuffer.toArray(),privateKey.getRSAPrivateKey()));
		circ.sendCell(cell);
		}	
	byte[] getCommandIntroduce2(CircuitNodeImpl circuitNode, CircuitImpl circ, TorPublicKey hsKey, int authType, byte[] authData, RendezvousPoint rend){
		HiddenServiceCell cell = HiddenServiceCellImpl.createCell(HiddenServiceCell.RELAY_COMMAND_INTRODUCE2, circ.getCircuitId());
		cell.putByte(3);
		cell.putByte(authType);
		cell.putByteArray(authData);
		cell.putInt((int)(new Date()).getTime());
		cell.putByteArray(rend.getAddress().getAddressDataBytes());
		cell.putInt(rend.getDirectoryPort());
		cell.putByteArray(rend.getOnionKey().toASN1Raw());
		cell.putInt(128);
		cell.putByteArray(rend.getRendKey().toASN1Raw());
		cell.putByteArray(rend.getRendezvousCookie());
		cell.putByteArray(circuitNode.getContext().getPublicValue().toByteArray());
		return cell.getCellBytes();
	}
	public void sendEstablishRendezvousCell(CircuitNodeImpl circuitNode, CircuitImpl circ){
		//generate rendezvous cookie
		TorRandom rand = new TorRandom();
		byte[] rendezvousCookie = new byte[20];
		for (int i = 0; i < rendezvousCookie.length; i++)
			rendezvousCookie[i] = (byte)rand.nextInt();
		HiddenServiceCell cell = HiddenServiceCellImpl.createCell(HiddenServiceCell.RELAY_COMMAND_ESTABLISH_RENDEZVOUS, circ.getCircuitId());
		cell.putByteArray(rendezvousCookie);
		circ.sendCell(cell);
	}
	
	
	private byte[] encrypt(byte[] data, RSAKey key){
		try{
			AsymmetricBlockCipher cip = new PKCS1Encoding(new RSABlindedEngine());
			cip.init(true, new RSAKeyParameters(key instanceof RSAPrivateKey, key.getModulus(), (key instanceof RSAPrivateKey? ((RSAPrivateKey)key).getPrivateExponent() : ((RSAPublicKey)key).getPublicExponent())));			
			byte[] retbytes = cip.processBlock(data, 0, data.length);
		    return retbytes;		    
		} catch (Exception e){
			logger.debug("Error in signing data " + e.getMessage());//error signing data
		}		
		return data;
	}
	/**
	 * 
	 * @param hsDirectory
	 * 			the directory of the hidden service configuration files private_key and hostname
	 * 			will instantiate a hidden service from tor HS configuration.
	 * @throws FileNotFoundException
	 */
	public static HiddenService createServiceFromDirectory(File hsDirectory, Logger logger) throws TorException{
		if (hsDirectory == null || !hsDirectory.isDirectory())
			throw new TorException("Directory is null or is not a directory.");
		else {
			FileInputStream fileScanner;
			try {
				fileScanner = new FileInputStream(hsDirectory = new File(hsDirectory.getAbsolutePath()+"/private_key"));
				if (!hsDirectory.exists())
					throw new TorException(new FileNotFoundException("Hidden Service Private Key file not found"));			
				byte[] fileData = new byte[(int)hsDirectory.length()];			
				fileScanner.read(fileData);
				TorPrivateKey privateKey = TorPrivateKey.createFromPEMBuffer(new String(fileData));				
				//Log: Successfully loaded Private Key
				fileScanner = new FileInputStream(hsDirectory = new File(hsDirectory.getParent()+"/hostname"));
				fileData = new byte[(int)hsDirectory.length()];
				fileScanner.read(fileData);
				return new HiddenService(privateKey, logger);				
			}catch (IOException e){
				throw new TorException(e);
			}
		}								
	}
	

	public String getHostname() {
		return hostname;
	}
	private void generateKeyPair() {
		privateKey = TorPrivateKey.generateNewKeypair();
	}

	/**
	 * Gets the service name.
	 * 
	 * @return the service name
	 */
	public String getServiceName() {
		return serviceName;
	}

	/**
	 * Sets the service name.
	 * 
	 * @param serviceName
	 *            the new service name
	 */
	public void setServiceName(String serviceName) {
		this.serviceName = serviceName;
	}

	/**
	 * Gets the service ports.
	 * 
	 * @return the service ports
	 */
	public PortRange getServicePorts() {
		return servicePorts;
	}

	/**
	 * Sets the service ports.
	 * 
	 * @param servicePorts
	 *            the new service ports
	 */
	public void setServicePorts(PortRange servicePorts) {
		this.servicePorts = servicePorts;
	}

	/**
	 * Gets the introduction points.
	 * 
	 * @return the introduction points
	 */
	public List<IntroductionPoint> getIntroductionPoints() {
		return new ArrayList<IntroductionPoint>(introCircuits.values());
	}

	/**
	 * Gets the hidden service descripter.
	 * 
	 * @return the hidden service descripter
	 */
	public HiddenServiceDescriptor getHiddenServiceDescriptor() {
		hiddenServiceDescriptor.generateDescriptorString();
		return hiddenServiceDescriptor;
	}

	/**
	 * Sets the private key.
	 * 
	 * @param privateKey
	 *            the new private key
	 */
	public void setPrivateKey(TorPrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	/**
	 * Generate service descriptor.
	 */
	public void generateServiceDescriptor() {
		if (privateKey != null) {
			hiddenServiceDescriptor = HiddenServiceDescriptor.generateServiceDescriptor(privateKey, logger);
			hiddenServiceDescriptor.generateDescriptorID();
		}
	}
	public void writeDescriptorToFile(File f){
		try{
			FileOutputStream fos = new FileOutputStream(f);
			hiddenServiceDescriptor.generateDescriptorString();
			fos.write(hiddenServiceDescriptor.getDescriptorString().getBytes());
			fos.flush();
		}catch (Exception e){
			
		}
	}
	/**
	 * Advertise descriptor.
	 */
	public boolean advertiseDescriptor(Directory directory) {	
		this.directory = directory;
		Random rand = new Random();
		ArrayList<Router> allDirectories;
		Router currDirectory;

		int replicas = 2;
		for (int i=0; i < replicas; i++){
			hiddenServiceDescriptor.setReplica(i);
			hiddenServiceDescriptor.generateDescriptorString();
			allDirectories = new ArrayList<Router>(((DirectoryImpl)directory).getHiddenServiceDirectories(hiddenServiceDescriptor.getDescriptorID()));
			int initSize = allDirectories.size();
			while (!allDirectories.isEmpty()){
					logger.debug("Posting to directory " + (initSize - allDirectories.size()+1) + "/" + initSize);
					currDirectory = allDirectories.remove(rand.nextInt(allDirectories.size()));
					if (hiddenServiceDescriptor.postServiceDescriptor(currDirectory))
						return true;				
			}			
		}
		return false;
	}

	public void initializeIntroPoints(Directory directory, CircuitManagerImpl cm){
		NodeChooser nodeChooser = new NodeChooser(cm, directory);
		List<Router> routers = directory.getAllRouters();
		HiddenServiceCircuitBuildHandler hiddenServiceBuildHandler = new HiddenServiceCircuitBuildHandler();
		TorRandom rand = new TorRandom();
		int numIntroPoints = rand.nextInt(4)+3;
		for (int i = 0; i < numIntroPoints && !routers.isEmpty(); i++){
			Router router = routers.remove(rand.nextInt(routers.size()));
			IntroductionPoint point = IntroductionPoint.createIntroPoint((RouterImpl)router);
			//need to be able to create HS circuits here, not used by any other connections
			try{
				List<Router> circrouters = new ArrayList<Router>();
				NodeChoiceConstraints ncc = new NodeChoiceConstraints();
				circrouters.add(nodeChooser.chooseEntryNode(ncc));
				circrouters.add(nodeChooser.chooseMiddleNode(ncc));
				circrouters.add(nodeChooser.chooseExitNodeForTarget(new StreamExitRequest(cm, point.getAddress(), point.getDirectoryPort()), ncc));
				Circuit introCircuit = cm.createNewCircuit();
				introCircuit.openCircuit(circrouters, hiddenServiceBuildHandler);
				introCircuits.put(introCircuit.getCircuitId(), point);
				sendEstablishIntroCell(((CircuitNodeImpl)introCircuit.getFinalCircuitNode()), ((CircuitImpl)introCircuit), point.getPublicKey());
				logger.debug("Sent intro cell to " + point.getAddress().toString());
				}catch (Exception e){
				throw new TorException(e);
			}
		}
			
	}
	private class HiddenServiceCircuitBuildHandler implements CircuitBuildHandler{

		@Override
		public void circuitBuildCompleted(Circuit circuit) {			
		}

		@Override
		public void circuitBuildFailed(String reason) {
			// TODO Auto-generated method stub
			logger.debug("intro circuit failed");
		}

		@Override
		public void connectionCompleted(Connection connection) {
			// TODO Auto-generated method stub
		}

		@Override
		public void connectionFailed(String reason) {
			// TODO Auto-generated method stub
			logger.debug("intro circuit failed");			
		}

		@Override
		public void nodeAdded(CircuitNode node) {
			// TODO Auto-generated method stub
			
		}
		
	}
	
	/**
	 * Adds the introduction point.
	 * 
	 * @param point
	 *            the point
	 */
	public void addIntroductionPoint(Router point) {
		hiddenServiceDescriptor.addRendPoint(point);
	}
	
	/**
	 * Establish introduction points.
	 */
	public void establishIntroductionPoints() {
		
	}
	public String toString() {
		hiddenServiceDescriptor.generateDescriptorString();
		return ("Hidden Service: " + serviceName + ":" + servicePorts.toString() + " Permanent ID : " + toHex(hiddenServiceDescriptor.getPermanentID()) + " Service Descriptor : \n" + hiddenServiceDescriptor.getDescriptorString());
	} 
	/**
	 * helper method, not sure if I need it or where to put it...
	 * @param bytes
	 * @return
	 */
	
	private static String toHex(byte[] bytes) {
	    BigInteger bi = new BigInteger(1, bytes);
	    return String.format("%0" + (bytes.length << 1) + "X", bi);
	}
	
}
