package org.torproject.jtor.hiddenservice;

import org.torproject.jtor.crypto.TorPublicKey;
import org.torproject.jtor.data.IPv4Address;

// TODO: Auto-generated Javadoc
/**
 * The Class RendezvousPoint.
 */
public class RendezvousPoint {
	
	/** The onion port. */
	private int onionPort;
	
	/**
	 * Gets the onion port.
	 * 
	 * @return the onion port
	 */
	public int getOnionPort() {
		return onionPort;
	}

	/**
	 * Sets the onion port.
	 * 
	 * @param onionPort
	 *            the new onion port
	 */
	public void setOnionPort(int onionPort) {
		this.onionPort = onionPort;
	}

	/**
	 * Gets the onion key.
	 * 
	 * @return the onion key
	 */
	public TorPublicKey getOnionKey() {
		return onionKey;
	}

	/**
	 * Sets the onion key.
	 * 
	 * @param onionKey
	 *            the new onion key
	 */
	public void setOnionKey(TorPublicKey onionKey) {
		this.onionKey = onionKey;
	}

	/**
	 * Gets the service key.
	 * 
	 * @return the service key
	 */
	public TorPublicKey getServiceKey() {
		return serviceKey;
	}

	/**
	 * Sets the service key.
	 * 
	 * @param serviceKey
	 *            the new service key
	 */
	public void setServiceKey(TorPublicKey serviceKey) {
		this.serviceKey = serviceKey;
	}

	/**
	 * Gets the rendezvous cookie.
	 * 
	 * @return the rendezvous cookie
	 */
	public byte[] getRendezvousCookie() {
		return rendezvousCookie;
	}

	/**
	 * Sets the rendezvous cookie.
	 * 
	 * @param rendezvousCookie
	 *            the new rendezvous cookie
	 */
	public void setRendezvousCookie(byte[] rendezvousCookie) {
		this.rendezvousCookie = rendezvousCookie;
	}

	/**
	 * Gets the ip address.
	 * 
	 * @return the ip address
	 */
	public IPv4Address getIpAddress() {
		return ipAddress;
	}

	/**
	 * Sets the ip address.
	 * 
	 * @param ipAddress
	 *            the new ip address
	 */
	public void setIpAddress(IPv4Address ipAddress) {
		this.ipAddress = ipAddress;
	}

	/**
	 * Gets the auth type.
	 * 
	 * @return the auth type
	 */
	public String getAuthType() {
		return authType;
	}

	/**
	 * Gets the auth data.
	 * 
	 * @return the auth data
	 */
	public byte[] getAuthData() {
		return authData;
	}

	/**
	 * Gets the identifier.
	 * 
	 * @return the identifier
	 */
	public byte[] getIdentifier() {
		return identifier;
	}

	/** The onion key. */
	private TorPublicKey onionKey;
	
	/** The service key. */
	private TorPublicKey serviceKey;
	
	/** The auth type. */
	private String authType;
	
	/** The auth data. */
	private byte[] authData;
	
	/** The identifier. */
	private byte[] identifier;
	
	/** The rendezvous cookie. */
	private byte[] rendezvousCookie;
	
	/** The ip address. */
	private IPv4Address ipAddress;
	
	/**
	 * Instantiates a new rendezvous point.
	 * 
	 * @param ipAddress
	 *            the ip address
	 * @param onionPort
	 *            the onion port
	 * @param serviceKey
	 *            the service key
	 */
	public RendezvousPoint(IPv4Address ipAddress, int onionPort, TorPublicKey serviceKey) {
		
	}
	
	/**
	 * Instantiates a new rendezvous point.
	 * 
	 * @param onionKey
	 *            the onion key
	 */
	public RendezvousPoint(TorPublicKey onionKey){
		
	}
		
	
}
