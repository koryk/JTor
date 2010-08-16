package org.torproject.jtor.hiddenservice;

import java.io.InputStream;
import java.util.List;
import java.util.Scanner;

import org.torproject.jtor.crypto.TorMessageDigest;
import org.torproject.jtor.crypto.TorPublicKey;
import org.torproject.jtor.crypto.TorSignature;
import org.torproject.jtor.data.HexDigest;
import org.torproject.jtor.data.IPv4Address;
import org.torproject.jtor.data.Timestamp;
import org.torproject.jtor.directory.impl.DocumentFieldParserImpl;
import org.torproject.jtor.directory.parsing.DocumentFieldParser;
import org.torproject.jtor.directory.parsing.DocumentObject;
import org.torproject.jtor.directory.parsing.DocumentParsingHandler;
import org.torproject.jtor.hiddenservice.publishing.IntroductionPoint;
import org.torproject.jtor.logging.Logger;

import com.sun.org.apache.xml.internal.security.utils.Base64;

public class HiddenServiceDescriptorParser {
	private DocumentFieldParser parser;
	private Scanner hiddenStream;
	public static Logger log;
	String descriptorID, secretID, protocolString = "", signature;
	Timestamp publicationTime;
	TorPublicKey pk;
	List<IntroductionPoint> introPoints;
	int version;
	boolean verified = false;

	public HiddenServiceDescriptorParser(InputStream is, Logger log){
		parser = new DocumentFieldParserImpl(is, log);
		this.log= log; 
		hiddenStream = new Scanner(is);
		parser.setDelimiter(" ");
		parser.setHandler(new DocumentParsingHandler(){
			@Override
			public void endOfDocument() {
				// TODO Auto-generated method stub
				HiddenServiceDescriptorParser.log.debug("Finished parsing descriptor");
			}

			@Override
			public void parseKeywordLine() {
				parseLine(parser);
			}
			
		});
		parser.startSignedEntity();
		parser.processDocument();
	}
	public HiddenServiceDescriptor parseDescriptor(){		
		return null;
	}
	public boolean isVerified(){
		return verified;
	}
	private void parseLine(DocumentFieldParser parser){
		String line = parser.getCurrentKeyword();
		if (line.equalsIgnoreCase("rendezvous-service-descriptor"))
			descriptorID = parser.parseString();
		if (line.equalsIgnoreCase("version"))
			version = parser.parseInteger();
		if (line.equalsIgnoreCase("permanent-key")){
			pk = parser.parsePublicKey();
			log.debug("parsed fingerprint" + pk.getFingerprint());
		}
		if (line.equalsIgnoreCase("secret-id-part"))
			secretID = parser.parseString();
		if (line.equalsIgnoreCase("publication-time"))
			publicationTime = parser.parseTimestamp();
		if (line.equalsIgnoreCase("protocol-versions"))
			while (parser.argumentsRemaining() > 0)
				protocolString += parser.parseString(); 
		if (line.equalsIgnoreCase("introduction-points"))
			parseIntroPoints(parser);
		if (line.startsWith("-----END")){
			while (parser.argumentsRemaining() > 0)
				parser.parseString();
			parser.endSignedEntity();
		}
		if (line.equalsIgnoreCase("signature"))
			verified = parser.verifySignedEntity(pk, parser.parseSignature());
		while (parser.argumentsRemaining() > 0)
			parser.parseString();
		log.debug("line " + line);
	}
	private void parseIntroPoints(DocumentFieldParser parser){
		
	}
}