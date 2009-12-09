package org.torproject.jtor.hiddenservice;

import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;

import org.torproject.jtor.crypto.TorPrivateKey;
import org.torproject.jtor.crypto.TorPublicKey;
import org.torproject.jtor.data.exitpolicy.PortRange;
import org.torproject.jtor.directory.Directory;
import org.torproject.jtor.directory.DirectoryServer;
import org.torproject.jtor.directory.Router;

// TODO: Auto-generated Javadoc
/**
 * The Class HiddenService.
 */
public class HiddenService {
	
	/** The introduction points. */
	private ArrayList<Router> introductionPoints = new ArrayList<Router>();
	
	/** The hidden service descriptor. */
	private ServiceDescriptor hiddenServiceDescriptor;
	
	/** The private key. */
	private TorPrivateKey privateKey;
	
	/** The public key. */
	private TorPublicKey publicKey;
	
	/** The service name. */
	private String serviceName;
	
	/** The service ports. */
	private PortRange servicePorts;
	
	private Directory directory;
	
	/**
	 * Instantiates a new hidden service.
	 * 
	 * @param serviceName
	 *            the service name
	 * @param servicePorts
	 *            the service ports
	 */
	public HiddenService(String serviceName, PortRange servicePorts, Directory directory) {
		this.serviceName = serviceName;
		this.servicePorts = servicePorts;
		this.directory = directory;
		generateKeyPair();
		generateServiceDescriptor();
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
		this.serviceName = serviceName;
		this.servicePorts = servicePorts;
		this.publicKey = publicKey;
		fetchPrivateKey();
	}
	private void fetchPrivateKey() {
		if (publicKey == null)
			return;
		//lookup private key based on public key file should be encrypted
	}
	/**
	 * Gets the public key.
	 * 
	 * @return the public key
	 */
	public TorPublicKey getPublicKey() {
		return publicKey;
	}
	private void generateKeyPair() {
		privateKey = TorPrivateKey.generateNewKeypair();
		publicKey = privateKey.getPublicKey();
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
	public ArrayList<Router> getIntroductionPoints() {
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
	public void setPrivateKey(TorPrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	/**
	 * Generate service descriptor.
	 */
	public void generateServiceDescriptor() {
		if (publicKey != null) {
			hiddenServiceDescriptor = ServiceDescriptor.generateServiceDescriptor(privateKey);
			hiddenServiceDescriptor.generateDescriptorID();
		}
	}
	
	/**
	 * Advertise descriptor.
	 */
	public void advertiseDescriptor() {	
		
		String descriptor = hiddenServiceDescriptor.getDescriptorString();
		final String path = "/tor/rendezvous/publish";
		ArrayList<DirectoryServer> authorities = new ArrayList<DirectoryServer>(directory.getDirectoryAuthorities());
		
		for (DirectoryServer server : authorities) {
		
	        // Create a socket to the host
	        int port = 80;
	        InetAddress addr = server.getAddress().toInetAddress();
	        try {
	        Socket socket = new Socket(addr, port);
	    
	        
	        BufferedWriter wr = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF8"));
	        wr.write("POST "+path+" HTTP/1.1\r\n");
	        
	        // Send data
	        wr.write(descriptor);
	        wr.flush();
	        } catch (Exception e) {
	        	System.out.println("advertised descriptor");//log post error
	        }
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
		return ("Hidden Service: " + serviceName + ":" + servicePorts.toString() + " Permanent ID : " + toHex(hiddenServiceDescriptor.getPermanentID()) + " Service Descriptor : \n" + hiddenServiceDescriptor.getDescriptorString() + " " + getPublicKey());
	} 
	private static String toHex(byte[] bytes) {
	    BigInteger bi = new BigInteger(1, bytes);
	    return String.format("%0" + (bytes.length << 1) + "X", bi);
	}
	
}
