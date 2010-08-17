package org.torproject.jtor.directory.impl;

import java.util.Date;

import org.torproject.jtor.TorException;
import org.torproject.jtor.crypto.TorPublicKey;
import org.torproject.jtor.data.HexDigest;
import org.torproject.jtor.data.IPv4Address;
import org.torproject.jtor.directory.Router;
import org.torproject.jtor.directory.RouterDescriptor;
import org.torproject.jtor.directory.RouterStatus;

public class RouterImpl implements Router, Comparable<RouterImpl> {
	static RouterImpl createFromRouterStatus(RouterStatus status) {
		return new RouterImpl(status);
	}

	private final HexDigest identityHash;
	protected RouterStatus status;
	private RouterDescriptor descriptor;

	protected RouterImpl(RouterStatus status) {
		identityHash = status.getIdentity();
		this.status = status;
	}

	void updateStatus(RouterStatus status) {
		if(!identityHash.equals(status.getIdentity()))
			throw new TorException("Identity hash does not match status update");
		this.status = status;
	}
	public RouterStatus getStatus() {
		return status;
	}

	void updateDescriptor(RouterDescriptor descriptor) {
		this.descriptor = descriptor;
	}

	public boolean isDescriptorDownloadable() {
		
		if(descriptor != null && descriptor.getDescriptorDigest().equals(status.getDescriptorDigest()))
			return false;
		
		final Date now = new Date();
		final long diff = now.getTime() - status.getPublicationTime().getDate().getTime();
		return diff > (1000 * 60 * 10);	
	}
	
	public HexDigest getDescriptorDigest() {
		return status.getDescriptorDigest();
	}

	public IPv4Address getAddress() {
		return status.getAddress();
	}

	public RouterDescriptor getCurrentDescriptor() {
		return descriptor;
	}

	public boolean hasFlag(String flag) {
		return status.hasFlag(flag);
	}

	public boolean isHibernating() {
		if(descriptor == null)
			return false;
		return descriptor.isHibernating();
	}

	public boolean isRunning() {
		return hasFlag("Running");
	}

	public boolean isValid() {
		return hasFlag("Valid");
	}

	public boolean isBadExit() {
		return hasFlag("BadExit");
	}

	public boolean isPossibleGuard() {
		return hasFlag("Guard");
	}

	public boolean isExit() {
		return hasFlag("Exit");
	}

	public boolean isFast() {
		return hasFlag("Fast");
	}

	public boolean isStable() {
		return hasFlag("Stable");
	}
	
	public boolean isHSDirectory() {
		return hasFlag("HSDir");
	}

	public int getDirectoryPort() {
		return status.getDirectoryPort();
	}

	public HexDigest getIdentityHash() {
		return identityHash;
	}
	
	public TorPublicKey getIdentityKey() {
		return descriptor.getIdentityKey();
	}

	public String getNickname() {
		return status.getNickname();
	}

	public int getOnionPort() {
		return status.getRouterPort();
	}

	public TorPublicKey getOnionKey() {
		return descriptor.getOnionKey();
	}

	public int getEstimatedBandwidth() {
		return status.getEstimatedBandwidth();
	}

	public int getMeasuredBandwidth() {
		return status.getMeasuredBandwidth();
	}

	public int getAverageBandwidth() {
		if(descriptor == null)
			return 0;
		return descriptor.getAverageBandwidth();
	}

	public int getBurstBandwidth() {
		if(descriptor == null)
			return 0;
		return descriptor.getBurstBandwidth();
	}

	public int getObservedBandwidth() {
		if(descriptor == null)
			return 0;
		return descriptor.getObservedBandwidth();
	}

	public boolean exitPolicyAccepts(IPv4Address address, int port) {
		if(descriptor == null)
			return false;

		if(address == null)
			return descriptor.exitPolicyAccepts(port);

		return descriptor.exitPolicyAccepts(address, port);
	}

	public boolean exitPolicyAccepts(int port) {
		return exitPolicyAccepts(null, port);
	}
	public int compareTo(RouterImpl router){
		byte[] data = this.getIdentityHash().getRawBytes(), odata = router.getIdentityHash().getRawBytes();
		return RouterImpl.compareRouterIDs(data, odata);
		
	}
	public static int compareRouterIDs(byte[] data, byte[] odata){
		int len = data.length;
		int lenb = odata.length;

		for (int i = 0; ; i++) {
		    int a = 0, b = 0;

		    if (i < len) {
			a = ((int) data[i]) & 0xff;
		    } else if (i >= lenb) {
			return 0;
		    }

		    if (i < lenb) {
			b = ((int) odata[i]) & 0xff;
		    }

		    if (a > b) {
			return 1;
		    }

		    if (b > a) {
			return -1;
		    }
		}

	}
}
