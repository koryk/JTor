package org.torproject.jtor.crypto;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.torproject.jtor.TorException;
import org.torproject.jtor.TorParsingException;

public class TorPrivateKey {
	
	static public TorPrivateKey generateNewKeypair() {
		KeyPairGenerator generator = createGenerator();
		generator.initialize(1024, new SecureRandom());
		KeyPair pair = generator.generateKeyPair();
		return new TorPrivateKey((RSAPrivateKey)pair.getPrivate(), (RSAPublicKey)pair.getPublic());
	}
	
	static KeyPairGenerator createGenerator() {
		try {
			return KeyPairGenerator.getInstance("RSA", "BC");
		} catch (NoSuchAlgorithmException e) {
			throw new TorException(e);
		} catch (NoSuchProviderException e) {
			throw new TorException(e);
		}
	}
	
	private final TorPublicKey publicKey;
	private final RSAPrivateKey privateKey;
	
	TorPrivateKey(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
		this.privateKey = privateKey;
		this.publicKey = new TorPublicKey(publicKey);
	}
	
	public TorPublicKey getPublicKey() {
		return publicKey;
	}
	
	public RSAPublicKey getRSAPublicKey() {
		return publicKey.getRSAPublicKey();
	}
	
	public RSAPrivateKey getRSAPrivateKey() {
		return privateKey;
	}
	public String toPEMFormat(){
		final StringWriter stringWriter = new StringWriter();
		final PEMWriter pemWriter = new PEMWriter(stringWriter);
		try {
		pemWriter.writeObject(privateKey);
		pemWriter.flush();		
		} catch (IOException e) {
			throw new TorException(e);			
		}
		return stringWriter.toString();	
	}
	static public TorPrivateKey createFromPEMBuffer(String buffer) {
		final PEMReader pemReader = new PEMReader( new StringReader(buffer));
		final KeyPair keyPair = readPEMPrivateKey(pemReader); 
		return new TorPrivateKey((RSAPrivateKey)keyPair.getPrivate(),(RSAPublicKey)keyPair.getPublic());
	}	
	static private KeyPair readPEMPrivateKey(PEMReader reader) {
		try {
			final Object ob = reader.readObject();
			return verifyObjectAsKey(ob);
		} catch (IOException e) {
			throw new TorException(e);
		}
	}
	static private KeyPair verifyObjectAsKey(Object ob) {
		if(ob instanceof KeyPair)
			return ((KeyPair) ob);
		else
			throw new TorParsingException("Failed to extract PEM private key.");
	}

}
