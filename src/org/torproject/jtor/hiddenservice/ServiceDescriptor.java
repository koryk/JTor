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
	public ServiceDescriptor(byte[] permanentID) {
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
		generateTimePeriod();
		TorMessageDigest digest = new TorMessageDigest();
		BigInteger result = BigInteger.valueOf(timePeriod);
		if (hasDescriptorCookie())
			result = result.or(new BigInteger(descriptorCookie));
		result = result.or(BigInteger.valueOf(replica));			
		digest.update(result.toByteArray());
		result = new BigInteger(digest.getDigestBytes()).or(new BigInteger(permanentID));
		digest.update(result.toByteArray());
		descriptorID = digest.getDigestBytes();
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
	 * Generate permanent id.
	 * 
	 * @param publicKey
	 *            the public key
	 * 
	 * @return the byte[]
	 */
	public static byte[] generatePermanentID(TorPublicKey publicKey) {
		TorMessageDigest digest = new TorMessageDigest();
		digest.update(publicKey.getRSAPublicKey().getEncoded());
		byte[] permanentID = new byte[PERMANENT_ID_SIZE];
		System.arraycopy(digest.getDigestBytes(),0,permanentID,0,10);
		return permanentID; 
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
