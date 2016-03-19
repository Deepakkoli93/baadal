package net.floodlightcontroller.baadal;

import java.util.Map;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.VlanVid;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IBaadalService extends IFloodlightService{

	public Map<IPv4Address, VlanVid> getIpToTag();
	
	public void addMacEntry(MacAddress mac, VlanVid vlanId);
	
	public boolean getInterVlanStatus();
}
