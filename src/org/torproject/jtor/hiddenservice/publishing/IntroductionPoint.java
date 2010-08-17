package org.torproject.jtor.hiddenservice.publishing;

import org.torproject.jtor.crypto.TorPrivateKey;
import org.torproject.jtor.crypto.TorPublicKey;
import org.torproject.jtor.directory.RouterStatus;
import org.torproject.jtor.directory.impl.RouterImpl;

public class IntroductionPoint extends RouterImpl{
	private TorPrivateKey keyPair;
	private String authType;
	protected IntroductionPoint(RouterStatus status) {
		super(status);
		//keypair for descriptor of IP
		keyPair = TorPrivateKey.generateNewKeypair();
	}
	public static IntroductionPoint createIntroPoint(RouterImpl router){
		IntroductionPoint point = new IntroductionPoint(router.getStatus());
		return point;
	}
	public RouterStatus getRouterStatus(){
		return status;
	}
	public TorPublicKey getPublicKey(){
		return keyPair.getPublicKey();
	}

}
