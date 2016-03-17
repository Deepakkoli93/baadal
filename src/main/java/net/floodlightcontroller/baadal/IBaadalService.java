package net.floodlightcontroller.baadal;

import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.VlanVid;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IBaadalService extends IFloodlightService{

	public void addMacEntry(MacAddress mac, VlanVid vlanId);
}
