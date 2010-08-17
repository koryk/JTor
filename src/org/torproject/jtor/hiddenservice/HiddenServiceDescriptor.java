package org.torproject.jtor.hiddenservice;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;
import org.torproject.jtor.TorException;
import org.torproject.jtor.circuits.CircuitManager;
import org.torproject.jtor.crypto.TorMessageDigest;
import org.torproject.jtor.crypto.TorPrivateKey;
import org.torproject.jtor.crypto.TorPublicKey;
import org.torproject.jtor.data.Base32;
import org.torproject.jtor.data.HexDigest;
import org.torproject.jtor.directory.Directory;
import org.torproject.jtor.directory.Router;
import org.torproject.jtor.directory.impl.DirectoryImpl;
import org.torproject.jtor.directory.impl.HttpConnection;
import org.torproject.jtor.logging.Logger;

import com.sun.org.apache.xml.internal.security.algorithms.JCEMapper.Algorithm;
import com.sun.org.apache.xml.internal.security.utils.Base64;
/**
 *  Author: Kory Kirk
 *  ServiceDescriptor is the class that represents the V2 Service Descriptor used for publishing 
 *  Hidden Services.
 */
public class HiddenServiceDescriptor {
	
	private final static int NUM_HS_ROUTERS = 6;
	
	public final static int NUMBER_OF_NON_CONSECUTIVE_REPLICA = 3;
	
	private final static int RETRY_COUNT = 5;
	
	/** The Constant PERMANENT_ID_SIZE. */
	private final static int PERMANENT_ID_SIZE = 10;
	
	private final static int DESCRIPTOR_ID_SIZE = 20;
	
	/** The descriptor VERSION. */
	private final static String VERSION = "2";
	
	/** The descriptor data. */
	private byte[] descriptorData;
	
	/** The time in which the descriptor is no longer valid */
	private int validUntil;
	
	/** The descriptor string. */
	private String descriptorString;	
	
	/** The permanent id. */
	private byte[] permanentID;
	
	/** The optional descriptor cookie. (for client authentication) */
	private byte[] descriptorCookie;
	
	/** The descriptor id. */
	private byte[] descriptorID;
	
	/** The secret id. */
	private byte[] secretID;
	
	/** The permanent key. */
	private TorPublicKey permanentKey;  
	
	/** The private key */
	private TorPrivateKey privateKey; 
	
	/** The time period. */
	private long timePeriod;
	
	/** The replica. */
	private int replica = 0;
	
	/** The date format. */
	private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	
	/** a list of the rendezvous points */
	private List<Router> rendPoints;
	
	private Logger logger; 
	
	/**
	 * Instantiates a new service descriptor.
	 * 
	 * @param permanentID
	 *            the permanent id
	 */
	private HiddenServiceDescriptor(byte[] permanentID, Logger logger) {
		rendPoints = new ArrayList<Router>();
		this.permanentID = permanentID;
		this.logger = logger;
	}
	
	/**
	 * Checks for descriptor cookie.
	 * 
	 * @return true, if successful
	 */
	public boolean hasDescriptorCookie(){
		return (descriptorCookie!=null);		
	}
	public boolean postServiceDescriptor(Router hsDirectoryRouter){		
		//OpenStreamResponse hsDirectoryStreamResponse;
		Socket directorySocket = null;
		try{
			directorySocket = new Socket(hsDirectoryRouter.getAddress().toString(), hsDirectoryRouter.getDirectoryPort());				
		} catch (Exception e) {
			logger.debug("Cannot connect to " + hsDirectoryRouter.getAddress() + " for publishing. " + e.getMessage());
			return false;//cannot connect to server on port
		}
		HttpConnection httpConnection;
		try {
			httpConnection = new HttpConnection(hsDirectoryRouter.getAddress().toString(), new BufferedReader(new InputStreamReader(directorySocket.getInputStream())), new BufferedWriter(new OutputStreamWriter(directorySocket.getOutputStream())));
			httpConnection.sendPostRequest("/tor/rendezvous2/publish/", getDescriptorString().getBytes());
			httpConnection.readResponse();
			logger.debug("HTTP response to POST on " + hsDirectoryRouter.getAddress() + " : " + httpConnection.getStatusCode() + ":" + httpConnection.getStatusMessage());
			if(httpConnection.getStatusCode() == 200){
				return true;
			} 		
		} catch (Exception e) {
			logger.debug("Cannot read from " + hsDirectoryRouter.getAddress() + " for publishing. " + e.getMessage());
		}
		return false;
	}
	
	
	/*
	 * Fetches service descriptor from 
	 * 
	 */
	public static HiddenServiceDescriptor fetchServiceDescriptor(String onionAddress, final Directory hiddenServiceDirectory, CircuitManager hsCircuit, Logger logger){		
		Random rand = new Random();
		List<Router> hsDirectories = new ArrayList<Router>(), allDirectories = hiddenServiceDirectory.getHiddenServiceDirectories();	
		HiddenServiceDescriptor returnDescriptor = null;
		//OpenStreamResponse hsDirectoryStreamResponse;
		int replicaTries = NUMBER_OF_NON_CONSECUTIVE_REPLICA;
		int retryCount;
		Socket directorySocket = null;
		for (int i = 0; i < replicaTries; i++){
		byte[] descriptorID = HiddenServiceDescriptor.getDescriptorID(Base32.base32Decode(onionAddress), null, i, logger);
			hsDirectories = ((DirectoryImpl)hiddenServiceDirectory).getHiddenServiceDirectories(descriptorID);			
			for (Router hsDirectoryRouter : hsDirectories) {
				retryCount = 0;
				try {
					/*hsDirectoryStreamResponse = hsCircuit.openExitStreamTo(hsDirectoryRouter.getAddress(), hsDirectoryRouter.getDirectoryPort());				
					  because of bug, not going over tor stream
					  HttpConnection httpConnection = new HttpConnection(hsDirectoryRouter.getAddress().toString(), new BufferedReader(new InputStreamReader(hsDirectoryStreamResponse.getStream().getInputStream())), new BufferedWriter(new OutputStreamWriter(hsDirectoryStreamResponse.getStream().getOutputStream())));								
					*/
					try{
						directorySocket = new Socket(hsDirectoryRouter.getAddress().toString(), hsDirectoryRouter.getDirectoryPort());				
					} catch (Exception e) {
						logger.debug("Cannot connect to " + hsDirectoryRouter.getAddress() + " for fetching. " + e.getMessage());
						continue;//cannot connect to server on port
					}
					HttpConnection httpConnection = new HttpConnection(hsDirectoryRouter.getAddress().toString(), new BufferedReader(new InputStreamReader(directorySocket.getInputStream())), new BufferedWriter(new OutputStreamWriter(directorySocket.getOutputStream())));
					try {
							httpConnection.sendGetRequest("/tor/rendezvous2/" + Base32.base32Encode(descriptorID));
							httpConnection.readResponse();
						} catch (TorException e) {
							if (retryCount >= RETRY_COUNT)
								break;
							Thread.sleep(500);
							logger.debug("Could not fetch V2 descriptor from " + hsDirectoryRouter.getAddress().toString());
							retryCount++;
						}
						logger.debug("HTTP response code for GET request on " + hsDirectoryRouter.getAddress().toString() + " : " + httpConnection.getStatusCode() + ":" + httpConnection.getStatusMessage());
						if(httpConnection.getStatusCode() == 200){
							Scanner bodyReader = new Scanner(httpConnection.getBodyReader());
							String descriptorBody = "";
							while (bodyReader.hasNextLine())
								descriptorBody += bodyReader.nextLine();						
							return parseServerDescriptor(descriptorBody);
						} 
					}
				catch (Exception e){
					throw new TorException(e);
				}
		    }
			hsDirectories.clear();
		}
		while (!allDirectories.isEmpty()){
			Router hsDirectoryRouter = allDirectories.remove(rand.nextInt(allDirectories.size()));
			for (int i = 0; i < replicaTries; i++){
				try{
				byte[] descriptorID = HiddenServiceDescriptor.getDescriptorID(Base32.base32Decode(onionAddress), null, i, logger);
				try{
					directorySocket = new Socket(hsDirectoryRouter.getAddress().toString(), hsDirectoryRouter.getDirectoryPort());				
				} catch (Exception e) {
					logger.debug("Cannot connect to " + hsDirectoryRouter.getAddress() + " for fetching. " + e.getMessage());
					continue;//cannot connect to server on port
				}
				HttpConnection httpConnection = new HttpConnection(hsDirectoryRouter.getAddress().toString(), new BufferedReader(new InputStreamReader(directorySocket.getInputStream())), new BufferedWriter(new OutputStreamWriter(directorySocket.getOutputStream())));
				try {
						httpConnection.sendGetRequest("/tor/rendezvous2/" + Base32.base32Encode(descriptorID));
						httpConnection.readResponse();
					} catch (TorException e) {						
						logger.debug("Could not fetch V2 descriptor from " + hsDirectoryRouter.getAddress().toString());
					}
					logger.debug("HTTP response code for GET request on " + hsDirectoryRouter.getAddress().toString() + " : " + httpConnection.getStatusCode() + ":" + httpConnection.getStatusMessage());
					if(httpConnection.getStatusCode() == 200){
						Scanner bodyReader = new Scanner(httpConnection.getBodyReader());
						String descriptorBody = "";
						while (bodyReader.hasNextLine())
							descriptorBody += bodyReader.nextLine();						
						return parseServerDescriptor(descriptorBody);
					} 
				}catch (Exception e){
					throw new TorException(e);
				}
			  }
			}
		return returnDescriptor;
	}
	private static HiddenServiceDescriptor parseServerDescriptor(String rawServiceDescriptor){
		Scanner sdScanner = new Scanner(rawServiceDescriptor);
		String line;
		int index;
		Hashtable<String,String> descriptorValues = new Hashtable<String, String>();
		while (sdScanner.hasNextLine()){
			line = sdScanner.nextLine();
			index = line.indexOf(" ");//the split between value name and value
			descriptorValues.put(line.substring(index), line.substring(index,line.length()+1));
		}
		return null;
	}
	/**
	 * Generate descriptor id.
	 */
	public void generateDescriptorID(){
		generateSecretID();
		descriptorID = new byte[DESCRIPTOR_ID_SIZE];
		byte[] data = new byte[DESCRIPTOR_ID_SIZE + secretID.length];
		System.arraycopy(data, 0, descriptorID, 0, DESCRIPTOR_ID_SIZE);
		System.arraycopy(secretID, 0, data, DESCRIPTOR_ID_SIZE, secretID.length);
		HexDigest digest = HexDigest.createDigestForData(data);
		System.arraycopy(digest.getRawBytes(), 0, descriptorID, 0, DESCRIPTOR_ID_SIZE);
	}
	/**
	 * Generate secret id.
	 */
	public void generateSecretID(){
		generateTimePeriod();
		byte[] tp = BigInteger.valueOf(timePeriod).toByteArray();
		byte[] repbytes = BigInteger.valueOf(replica).toByteArray();
		int len = tp.length + (hasDescriptorCookie()? descriptorCookie.length : 0) + repbytes.length;  
		byte[] data = new byte[len];
		System.arraycopy(data, 0, tp, 0, tp.length);
		if (hasDescriptorCookie())
			System.arraycopy(descriptorCookie, 0, data, tp.length, descriptorCookie.length);
		System.arraycopy(repbytes, 0, data, data.length-repbytes.length, repbytes.length);
		secretID = HexDigest.createDigestForData(data).getRawBytes();
	}
	public void setPrivateKey(TorPrivateKey privKey) {
		this.privateKey = privKey;
	}
	
	/**
	 * Generate time period.
	 */
	public void generateTimePeriod() {
		long currentTime = (new Date()).getTime();
		timePeriod = (int)((currentTime + (((int)permanentID[0]) * 337.5)) / 86400);
	}
	
	/**
	 * 
	 * 
	 * Generate Service Descriptor.
	 * 
	 * @param publicKey
	 *            the public key
	 * 
	 * @return a new Service Descriptor
	 */
	
	public static HiddenServiceDescriptor generateServiceDescriptor(TorPrivateKey privKey, Logger logger){
		TorPublicKey publicKey = privKey.getPublicKey();		
		byte[] permanentID = new byte[PERMANENT_ID_SIZE];
		System.arraycopy(publicKey.getFingerprint().getRawBytes(), 0, permanentID, 0, PERMANENT_ID_SIZE);
		HiddenServiceDescriptor ret = new HiddenServiceDescriptor(permanentID, logger);
		ret.setPrivateKey(privKey);
		ret.setPermanentKey(publicKey);
		return ret;
	}
	public static HiddenServiceDescriptor generateServiceDescriptor(TorPublicKey key, Logger logger){
		byte[] permanentID = new byte[PERMANENT_ID_SIZE];
		System.arraycopy(key.getFingerprint().getRawBytes(), 0, permanentID, 0, PERMANENT_ID_SIZE);
		HiddenServiceDescriptor hsd = new HiddenServiceDescriptor(permanentID, logger);
		return hsd;
	}
	public TorPublicKey getPermanentKey() {
		return permanentKey;
	}

	public void setPermanentKey(TorPublicKey permanentKey) {
		this.permanentKey = permanentKey;
	}
	
	/**
	 * generates the descriptorString before advertisement
	 * 
	 */
	public void generateDescriptorString() throws TorException{
		generateDescriptorID();	
		descriptorString = "rendezvous-service-descriptor " + formatDescriptorID() + "\n";
		descriptorString += "version " + VERSION + "\n";
		descriptorString += "permanent-key \n" + permanentKey.toPEMFormat() + "\n";
		descriptorString += "secret-id-part " + formatSecretID() + "\n";
		descriptorString += "publication-time " + getPublicationTime() + "\n";
		descriptorString += "protocol-versions V2 \n";
		descriptorString += "introduction-points\n";
		descriptorString += "-----BEGIN MESSAGE-----\n";		
		/**all the introduction points base64 encoded if descriptor cookie is present, then list is encrypted with AES in CTR mode with a random
	       initialization vector of 128 bits that is written to
	       the beginning of the encrypted string, and the "descriptor-cookie" as
	       secret key of 128 bits length. **/
		byte[] introPoints = null;
		if (!hasDescriptorCookie())
			introPoints = getIntroductionPointString().getBytes();
		else {//encrypt it
			byte[] ivBytes = getRandomKey();
			byte[] keyBytes = getDescriptorCookie();
			IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
			SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
			try{
				Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
				cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			    ByteArrayInputStream bIn = new ByteArrayInputStream(getIntroductionPointString().getBytes());
			    CipherInputStream cIn = new CipherInputStream(bIn, cipher);
			    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			    bOut.write(ivBytes);
			    int ch;
			    while ((ch = cIn.read()) >= 0) {
			      bOut.write(ch);
			    }
			    
			    introPoints  = bOut.toByteArray();
			} catch (Exception e) {
				throw new TorException(e);
			}
			
		}
		descriptorString += Base64.encode(introPoints);
		descriptorString += "\n-----END MESSAGE-----\n";
		String sigString = getSignature(descriptorString);
		descriptorString += "signature \n" + "-----BEGIN SIGNATURE-----\n" + sigString  + "\n" + "-----END SIGNATURE-----";
		//add signature string using private key.
	}
	private String getSignature(String stringData){
		TorMessageDigest digest = new TorMessageDigest();	    	
	    digest.update(descriptorString);
	    byte[] digestBytes = digest.getDigestBytes();
		byte[] signature = sign(digestBytes);		
		return Base64.encode(signature);
	}

	private byte[] sign(byte[] data){
		try{
			/*Signature signature = Signature.getInstance("SHA1withRSA", "BC");
	    	signature.initSign(privateKey.getRSAPrivateKey());  
	    	signature.update(data);
	    	signature.getAlgorithm();
			because bc encodes theirs w/ DER
			*/
			AsymmetricBlockCipher cip = new PKCS1Encoding(new RSABlindedEngine());
			cip.init(true, new RSAKeyParameters(true, privateKey.getRSAPrivateKey().getModulus(), privateKey.getRSAPrivateKey().getPrivateExponent()));			
			byte[] retbytes = cip.processBlock(data, 0, data.length);
		    return retbytes;		    
		} catch (Exception e){
			logger.debug("Error in signing data " + e.getMessage());//error signing data
		}		
		return data;
	}


	public byte[] getRandomKey() {
		byte[] retKey = new byte[16];
		Random rndGen = new Random();
		rndGen.nextBytes(retKey);
		return retKey;
	}
	public static byte[] getDescriptorID(byte[] permanentID, byte[] descriptorCookie, int replica, Logger logger) {
		HiddenServiceDescriptor descriptor = new HiddenServiceDescriptor(permanentID, logger);
		descriptor.setDescriptorCookie(descriptorCookie);
		descriptor.setReplica(replica);
		descriptor.generateDescriptorID();
		return descriptor.getDescriptorID();
	}
	private String getIntroductionPointString() {
		String retVal = "";
		for (Router r : rendPoints){
		 retVal += "introduction-point " + r.getIdentityHash() +"\n";
		 retVal += "ip-address " + r.getAddress().toString() + "\n";
		 retVal += "onion-port " + r.getOnionPort() + "\n";
		 retVal += "onion-key \n" + r.getOnionKey().toPEMFormat() + "\n";
		 retVal += "service-key \n" + getPermanentKey().toPEMFormat() + "\n";
		 //retVal += "introduction-authentication " + 
		}
		return retVal;
	}
	public void addRendPoint(Router r) {
		rendPoints.add(r);
	}
	/*
	 * periodically changing identifier of 160 bits formatted as 32 base32
	 */
	private String formatSecretID() {
		byte[] secret = new byte[20];
		System.arraycopy(secretID, 0, secret, 0, 20);
		return Base32.base32Encode(secret);
	}
	private String formatDescriptorID() {
		return Base32.base32Encode(descriptorID);
	}
	public String getOnionAddress() {
		return Base32.base32Encode(permanentID);
	}
	/**
	 * Encode descriptor.
	 */

	//getters
	/**
	 * 
	 * 
	 * Gets the publication time.
	 * @return the publication time
	 */
	public String getPublicationTime() {
		return dateFormat.format(new Date());
	}
	
	/**
	 * Gets the replica.
	 *
	 * 
	 * @return the replica
	 * 
	 */
	public int getReplica() {
		return replica;
	}

	/**
	 * Gets the time period.
	 * 
	 * @return the time period
	 */
	public long getTimePeriod() {
		return timePeriod;
	}
	
	/**
	 * Gets the descriptor string.
	 * 
	 * @return the descriptor string
	 */
	public String getDescriptorString() {
		return descriptorString;
	}
	
	/**
	 * Gets the descriptor.
	 * 
	 * @return the descriptor
	 */
	public byte[] getDescriptor() {
		return descriptorData;
	}
	
	/**
	 * Gets the permanent id.
	 * 
	 * @return the permanent id
	 */
	public byte[] getPermanentID() {
		return permanentID;
	}
	
	
	/**
	 * Gets the descriptor cookie.
	 * 
	 * @return the descriptor cookie
	 */
	public byte[] getDescriptorCookie() {
		return descriptorCookie;
	}
	
	//setters
	/**
	 * Sets the replica.
	 * 
	 * @param replica
	 *            the new replica
	 */
	public void setReplica(int replica) {
		this.replica = replica;
	}

	/**
	 * Sets the permanent id.
	 * 
	 * @param permenantID
	 *            the new permanent id
	 */
	public void setPermanentID(byte[] permenantID) {
		this.permanentID = permenantID;
	}
	
	/**
	 * Sets the descriptor cookie.
	 * 
	 * @param descriptorCookie
	 *            the new descriptor cookie
	 */
	public void setDescriptorCookie(byte[] descriptorCookie) {
		this.descriptorCookie = descriptorCookie;
	}
	
	/**
	 * Gets the descriptor data.
	 * 
	 * @return the descriptor data
	 */
	public byte[] getDescriptorData() {
		return descriptorData;
	}
	
	/**
	 * Gets the descriptor id.
	 * 
	 * @return the descriptor id
	 */
	public byte[] getDescriptorID() {
		return descriptorID;
	}

}
