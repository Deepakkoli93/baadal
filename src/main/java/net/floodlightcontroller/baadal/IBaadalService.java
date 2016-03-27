package net.floodlightcontroller.baadal;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.VlanVid;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IBaadalService extends IFloodlightService{

	public Map<IPv4Address, VlanVid> getIpToTag();
	
	public void addIpToTag(ConcurrentHashMap<IPv4Address, VlanVid> ipToTag);
	
	public boolean getInterVlanStatus();
	
	// get policy map
	public ConcurrentHashMap<IPv4Address, ConcurrentHashMap<IPv4Address, Boolean>> getInterVmPolicy();
	
	// add a policy
	public void addPolicy(ConcurrentHashMap<IPv4Address, ConcurrentHashMap<IPv4Address, Boolean>> interVmPolicy);
}
