package org.torproject.jtor.hiddenservice;

import org.torproject.jtor.circuits.cells.Cell;

public interface HiddenServiceCell extends Cell{
	final static int RELAY_COMMAND_ESTABLISH_INTRO = 32;
	final static int RELAY_COMMAND_ESTABLISH_RENDEZVOUS = 33; 
	final static int RELAY_COMMAND_INTRODUCE1 = 34;
	final static int RELAY_COMMAND_INTRODUCE2 = 35;
	final static int RELAY_COMMAND_RENDEZVOUS1 = 36;
	final static int RELAY_COMMAND_RENDEZVOUS2 = 37;
	final static int RELAY_COMMAND_INTRO_ESTABLISHED = 38;
	final static int RELAY_COMMAND_RENDEZVOUS_ESTABLISHED = 39;
	final static int RELAY_COMMAND_INTRODUCE_ACK = 40;
	final static int RELAY_COMMAND_INTRODUCE1V = 41;
}
