package org.torproject.jtor.hiddenservice;

import org.torproject.jtor.crypto.TorPublicKey;
import org.torproject.jtor.data.exitpolicy.PortRange;

// TODO: Auto-generated Javadoc
/**
 * The Class HiddenServiceConnection.
 */
public class HiddenServiceConnection {
	
	/** The onion address. */
	String onionAddress;
	
	/** The port range. */
	PortRange portRange;
	
	/** The rendezvous cookie. */
	byte[] rendezvousCookie;
	
	/**
	 * Instantiates a new hidden service connection.
	 * 
	 * @param onionAddress
	 *            the onion address
	 */
	public HiddenServiceConnection(String onionAddress) {
		
	}
	
	/**
	 * Instantiates a new hidden service connection.
	 * 
	 * @param serviceKey
	 *            the service key
	 */
	public HiddenServiceConnection(TorPublicKey serviceKey) {
		
	}
	
	/**
	 * Parses the onion address.
	 */
	public void parseOnionAddress() {
		
	}
	
	/**
	 * Generate rendezvous cookie.
	 */
	public void generaterendezvousCookie() {
		
	}
	
	/**
	 * Gets the onion address.
	 * 
	 * @return the onion address
	 */
	public String getOnionAddress() {
		return onionAddress;
	}
	
	/**
	 * Sets the onion address.
	 * 
	 * @param onionAddress
	 *            the new onion address
	 */
	public void setOnionAddress(String onionAddress) {
		this.onionAddress = onionAddress;
	}
	
	/**
	 * Gets the port range.
	 * 
	 * @return the port range
	 */
	public PortRange getPortRange() {
		return portRange;
	}
	
	/**
	 * Sets the port range.
	 * 
	 * @param portRange
	 *            the new port range
	 */
	public void setPortRange(PortRange portRange) {
		this.portRange = portRange;
	}
	
	/**
	 * Gets the rendezvous cookie.
	 * 
	 * @return the rendezvous cookie
	 */
	public byte[] getrendezvousCookie() {
		return rendezvousCookie;
	}
	
	/**
	 * Fetch service descriptor.
	 */
	public void fetchServiceDescriptor() {
		
	}
	
	/**
	 * Open rendezvous points.
	 */
	public void openRendevouzPoints() {
		
	}
	
}
