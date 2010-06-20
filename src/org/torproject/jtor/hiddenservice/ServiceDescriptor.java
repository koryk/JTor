package org.torproject.jtor.hiddenservice;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.torproject.jtor.TorException;
import org.torproject.jtor.crypto.TorMessageDigest;
import org.torproject.jtor.crypto.TorPrivateKey;
import org.torproject.jtor.crypto.TorPublicKey;
import org.torproject.jtor.data.Base32;
import org.torproject.jtor.data.HexDigest;
import org.torproject.jtor.directory.Router;

import com.sun.org.apache.xml.internal.security.utils.Base64;
/**
 *  Author: Kory Kirk
 *  ServiceDescriptor is the class that represents the V2 Service Descriptor used for publishing 
 *  Hidden Services.
 */
public class ServiceDescriptor {
	
	/** The Constant PERMANENT_ID_SIZE. */
	private final static int PERMANENT_ID_SIZE = 10;
	
	/** The descriptor VERSION. */
	private final static String VERSION = "2";
	
	/** The descriptor data. */
	private byte[] descriptorData;
	
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
	
	/**
	 * Instantiates a new service descriptor.
	 * 
	 * @param permanentID
	 *            the permanent id
	 */
	private ServiceDescriptor(byte[] permanentID) {
		rendPoints = new ArrayList<Router>();
		this.permanentID = permanentID;
	}
	
	/**
	 * Checks for descriptor cookie.
	 * 
	 * @return true, if successful
	 */
	public boolean hasDescriptorCookie(){
		return (descriptorCookie!=null);		
	}
	
	/*
	 * 
	 */
	
	/**
	 * Generate descriptor id.
	 */
	public void generateDescriptorID(){
		generateSecretID();
		TorMessageDigest digest = new TorMessageDigest();
		BigInteger result = new BigInteger(secretID);
		result = new BigInteger(digest.getDigestBytes()).or(new BigInteger(permanentID));
		digest.update(result.toByteArray());
		descriptorID = digest.getDigestBytes();
	}
	public void generateSecretID(){
		generateTimePeriod();
		TorMessageDigest digest = new TorMessageDigest();
		BigInteger result = BigInteger.valueOf(timePeriod);
		if (hasDescriptorCookie())
			result = result.or(new BigInteger(descriptorCookie));
		result = result.or(BigInteger.valueOf(replica));			
		digest.update(result.toByteArray());
		secretID = digest.getDigestBytes();
	}
	public void setPrivateKey(TorPrivateKey privKey) {
		this.privateKey = privKey;
	}
	
	/**
	 * Generate time period.
	 */
	public void generateTimePeriod() {
		long currentTime = (new Date()).getTime();
		timePeriod = currentTime + ((int)(permanentID[0] * 86400 / 256)) / 86400;
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
	
	public static ServiceDescriptor generateServiceDescriptor(TorPrivateKey privKey){
		TorPublicKey publicKey = privKey.getPublicKey();		
		byte[] permanentID = new byte[PERMANENT_ID_SIZE];
		System.arraycopy(publicKey.getFingerprint().getRawBytes(), 0, permanentID, 0, PERMANENT_ID_SIZE);
		ServiceDescriptor ret = new ServiceDescriptor(permanentID);
		ret.setPrivateKey(privKey);
		ret.setPermanentKey(publicKey);
		return ret;
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
		//supported versions - not sure about this yet
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
		descriptorString += "signature \n";
		//add signature string using private key.
	}
	public byte[] getRandomKey() {
		byte[] retKey = new byte[16];
		Random rndGen = new Random();
		rndGen.nextBytes(retKey);
		return retKey;
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
		return Base32.base32Encode(secretID);
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
	public void encodeDescriptor() {
		
	}

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
