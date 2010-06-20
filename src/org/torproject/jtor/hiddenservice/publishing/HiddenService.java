package org.torproject.jtor.hiddenservice.publishing;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.torproject.jtor.TorException;
import org.torproject.jtor.crypto.TorPrivateKey;
import org.torproject.jtor.crypto.TorPublicKey;
import org.torproject.jtor.data.exitpolicy.PortRange;
import org.torproject.jtor.directory.Directory;
import org.torproject.jtor.directory.DirectoryServer;
import org.torproject.jtor.directory.Router;
import org.torproject.jtor.hiddenservice.ServiceDescriptor;

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
	
	public TorPrivateKey getPrivateKey() {
		return privateKey;
	}
	/** The service name. */
	private String serviceName;
	
	/** The service ports. */
	private PortRange servicePorts;
	
	/** the host name .onion address */
	private String hostname;
	
	private Directory directory;
	
	public HiddenService(String serviceName, PortRange servicePorts, TorPrivateKey key){
		
	}
	public HiddenService(PortRange servicePorts, TorPrivateKey key){
		
	}
	public HiddenService(TorPrivateKey key){
		this.privateKey = key;
		generateServiceDescriptor();
	}
	
	/**
	 * Instantiates a brand new hidden service.
	 * 
	 * @param serviceName
	 *            the service name
	 * @param servicePorts
	 *            the service's ports
	 */
	public HiddenService(String serviceName, PortRange servicePorts, Directory directory) {
		this.serviceName = serviceName;
		this.servicePorts = servicePorts;
		this.directory = directory;
		generateKeyPair();
		generateServiceDescriptor();
	}
	/**
	 * 
	 * @param hsDirectory
	 * 			the directory of the hidden service configuration files private_key and hostname
	 * 			will instantiate a hidden service from tor HS configuration.
	 * @throws FileNotFoundException
	 */
	public static HiddenService createServiceFromDirectory(File hsDirectory) throws TorException{
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
				return new HiddenService(privateKey);				
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
	public ArrayList<Router> getIntroductionPoints() {
		return introductionPoints;
	}

	/**
	 * Gets the hidden service descripter.
	 * 
	 * @return the hidden service descripter
	 */
	public ServiceDescriptor getHiddenServiceDescriptor() {
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
	        wr.close();
	        } catch (Exception e) {
	        	//log post error
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
