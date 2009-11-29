package org.torproject.jtor.hiddenservice;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.torproject.jtor.TorException;
import org.torproject.jtor.crypto.TorMessageDigest;
import org.torproject.jtor.crypto.TorPublicKey;

// TODO: Auto-generated Javadoc
/**
 * The Class ServiceDescriptor.
 */
public class ServiceDescriptor {
	
	/** The Constant PERMANENT_ID_SIZE. */
	private final static int PERMANENT_ID_SIZE = 10;
	
	/** The Constant VERSION. */
	private final static String VERSION = "2";
	
	/** The descriptor data. */
	private byte[] descriptorData;
	
	/** The descriptor string. */
	private String descriptorString;	
	
	/** The permanent id. */
	private byte[] permanentID;
	
	/** The descriptor cookie. */
	private byte[] descriptorCookie;
	
	/** The descriptor id. */
	private byte[] descriptorID;
	
	/** The secret id. */
	private byte[] secretID;
	
	/** The permanent key. */
	private TorPublicKey permanentKey;  
	
	
	/** The time period. */
	private long timePeriod;
	
	/** The replica. */
	private int replica = 0;
	
	/** The date format. */
	private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	
	
	/**
	 * Instantiates a new service descriptor.
	 * 
	 * @param permanentID
	 *            the permanent id
	 */
	private ServiceDescriptor(byte[] permanentID) {
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
	
	
	/**
	 * Generate time period.
	 */
	public void generateTimePeriod() {
		long currentTime = (new Date()).getTime();
		timePeriod = currentTime + ((int)permanentID[0] * 86400 / 256) / 86400;
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
	
	public static ServiceDescriptor generateServiceDescriptor(TorPublicKey publicKey){
		TorMessageDigest digest = new TorMessageDigest();
		digest.update(publicKey.getRSAPublicKey().getEncoded());
		byte[] permanentID = new byte[PERMANENT_ID_SIZE];
		System.arraycopy(digest.getDigestBytes(),0,permanentID,0,PERMANENT_ID_SIZE);
		ServiceDescriptor ret = new ServiceDescriptor(permanentID);
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
	 * Should these fields be in quotes like in the spec?
	 * "rendezvous-service-descriptor" descriptor-id NL
	 * 
	 */
	public void generateDescriptorString() {
		generateDescriptorID();
		descriptorString = "rendezvous-service-descriptor " + formatDescriptorID() + "\n";
		descriptorString += "version " + VERSION + "\n";
		descriptorString += "permanent-key " + permanentKey.hashCode() + "\n";
		descriptorString += "secret-id-part " + formatSecretID() + "\n";
		descriptorString += "publication-time " + getPublicationTime() + "\n";
		//supported versions - not sure about this yet
		descriptorString += "protocol-versions V2 \n";
		descriptorString += "introduction-points\n";
		descriptorString += "-----BEGIN MESSAGE-----";		
		/**all the introduction points base64 encoded if descriptor cookie is present, then list is encrypted with AES in CTR mode with a random
	       initialization vector of 128 bits that is written to
	       the beginning of the encrypted string, and the "descriptor-cookie" as
	       secret key of 128 bits length. **/
		descriptorString += "-----END MESSAGE-----\n";
		descriptorString += "signature \n";
		//add signature string using private key.
	}
	/*
	 * periodically changing identifier of 160 bits formatted as 32 base32
	 */
	private String formatSecretID() {
		return "";
	}
	private String formatDescriptorID() {
		return "";
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
