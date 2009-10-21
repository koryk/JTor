package org.torproject.jtor.hiddenservice;

import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;

import org.torproject.jtor.crypto.TorPublicKey;
import org.torproject.jtor.data.exitpolicy.PortRange;

// TODO: Auto-generated Javadoc
/**
 * The Class HiddenService.
 */
public class HiddenService {
	
	/** The introduction points. */
	private ArrayList<IntroductionPoint> introductionPoints = new ArrayList<IntroductionPoint>();
	
	/** The hidden service descripter. */
	private ServiceDescriptor hiddenServiceDescriptor;
	
	/** The private key. */
	private RSAPrivateKey privateKey;
	
	/** The public key. */
	private TorPublicKey publicKey;
	
	/** The service name. */
	private String serviceName;
	
	/** The service ports. */
	private PortRange servicePorts;
	
	/**
	 * Instantiates a new hidden service.
	 * 
	 * @param serviceName
	 *            the service name
	 * @param servicePorts
	 *            the service ports
	 */
	public HiddenService(String serviceName, PortRange servicePorts) {
		
	}
	
	/**
	 * Gets the public key.
	 * 
	 * @return the public key
	 */
	public TorPublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Sets the public key.
	 * 
	 * @param publicKey
	 *            the new public key
	 */
	public void setPublicKey(TorPublicKey publicKey) {
		this.publicKey = publicKey;
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
	public ArrayList<IntroductionPoint> getIntroductionPoints() {
		return introductionPoints;
	}

	/**
	 * Gets the hidden service descripter.
	 * 
	 * @return the hidden service descripter
	 */
	public ServiceDescriptor getHiddenServiceDescripter() {
		return hiddenServiceDescriptor;
	}

	/**
	 * Sets the private key.
	 * 
	 * @param privateKey
	 *            the new private key
	 */
	public void setPrivateKey(RSAPrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	/**
	 * Instantiates a new hidden service.
	 * 
	 * @param serviceName
	 *            the service name
	 * @param servicePorts
	 *            the service ports
	 * @param publicKey
	 *            the public key
	 */
	public HiddenService(String serviceName, PortRange servicePorts, TorPublicKey publicKey) {
		
	}
	
	/**
	 * Generate keys.
	 */
	public void generateKeys() {
		
	}
	
	/**
	 * Generate service descripter.
	 */
	public void generateServiceDescriptor() {
		
	}
	
	/**
	 * Advertise descriptor.
	 */
	public void AdvertiseDescriptor() {
		
	}
	
	/**
	 * Adds the introduction point.
	 * 
	 * @param point
	 *            the point
	 */
	public void addIntroductionPoint(IntroductionPoint point) {
		introductionPoints.add(point);
	}
	
	/**
	 * Establish introduction points.
	 */
	public void establishIntroductionPoints() {
		
	}
	
}
