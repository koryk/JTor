package org.torproject.jtor.hiddenservice;

import org.torproject.jtor.crypto.TorPrivateKey;
import org.torproject.jtor.crypto.TorPublicKey;
import org.torproject.jtor.data.HexDigest;
import org.torproject.jtor.data.IPv4Address;
import org.torproject.jtor.directory.Router;
import org.torproject.jtor.directory.RouterDescriptor;
import org.torproject.jtor.directory.RouterStatus;
import org.torproject.jtor.directory.impl.RouterImpl;

// TODO: Auto-generated Javadoc
/**
 * The Class RendezvousPoint.
 */
public class RendezvousPoint extends RouterImpl{
	TorPrivateKey keys;	
	byte[] rendCookie = new byte[20];
	/**
	 * Instantiates a new rendezvous point.
	 * 
	 * @param RouterStatus 
	 *            the RouterStatus object
	 */
	public RendezvousPoint(RouterStatus status){
		super(status);
	}
	public byte[] getRendezvousCookie(){
		return rendCookie;
	}
	public void setRendezvousCookie(byte[] cookie){
		rendCookie = cookie;
	}
	public void setOnionKey(TorPrivateKey keys){
		this.keys = keys;
	}
	public TorPublicKey getRendKey(){
		if (keys == null)
			return null;
		else
			return keys.getPublicKey();
	}
}
