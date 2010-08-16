package org.torproject.jtor.hiddenservice;

import org.torproject.jtor.circuits.impl.CellImpl;

public class HiddenServiceCellImpl extends CellImpl implements HiddenServiceCell {



	protected HiddenServiceCellImpl(int circuitId, int command) {
		super(circuitId, command);
		// TODO Auto-generated constructor stub
	}

	public static HiddenServiceCell createCell(int cell, int circuit){
		HiddenServiceCell HSCell = new HiddenServiceCellImpl(circuit, cell);				
		return HSCell;
	}
}
