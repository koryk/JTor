package org.torproject.jtor.hiddenservice;




import org.torproject.jtor.Tor;
import org.torproject.jtor.data.exitpolicy.PortRange;
import org.torproject.jtor.directory.Directory;
import org.torproject.jtor.directory.DirectoryServer;
import org.torproject.jtor.directory.Router;

public class HiddenServiceTest {
	public static void main(String args[]) {
		
		Tor tor = new Tor();
		tor.start();
		Directory d = tor.getDirectory();
		HiddenService testHiddenService = new HiddenService("JTor Test hidden service", PortRange.createFromString("6112-6120"), d);
		for (int i = 0; i < 4; i++)
			testHiddenService.addIntroductionPoint(d.getRandomDirectoryServer());
		testHiddenService.advertiseDescriptor();
		
		System.out.println(testHiddenService);
	}
	


}
