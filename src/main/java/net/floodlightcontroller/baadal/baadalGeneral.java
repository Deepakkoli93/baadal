package net.floodlightcontroller.baadal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;

import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxmVlanVid;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.VlanVid;

//import net.floodlightcontroller.baadal._baadalUtils.*;

public class baadalGeneral {
	protected static Logger logger;
	private Map<MacAddress, OFPort> macToPort;
	Map<IPv4Address, MacAddress> ipToMac;
	baadalUtils _baadalUtils;
	List<MacAddress> dpid_hosts;
	Map<MacAddress, VlanVid> macToTag;
	List<Map<OFPort, List<VlanVid> > > portToTag;
	IPv4Address hostip;
	
	public baadalGeneral(Logger _logger, baadalUtils bu, List<MacAddress> _dpid_hosts, Map<MacAddress, VlanVid> _macToTag, List<Map<OFPort, List<VlanVid> > > _portToTag, IPv4Address _hostip){
		logger = _logger;
		macToPort = new HashMap<MacAddress, OFPort>();
		ipToMac = new HashMap<IPv4Address, MacAddress> ();
		_baadalUtils = bu;
		dpid_hosts = _dpid_hosts;
		macToTag = _macToTag;
		portToTag = _portToTag;
		hostip = _hostip;
	}

	protected Command processPacketIn(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		if (eth.getEtherType() == EthType.VLAN_FRAME){
			logger.info("it's a vlan packet!");
		IPv4 ipv44 = (IPv4) eth.getPayload();
		if(!(ipv44.getSourceAddress().equals(IPv4Address.of("10.0.0.1")) ||ipv44.getDestinationAddress().equals(IPv4Address.of("10.0.0.1")) 
				||ipv44.getSourceAddress().equals(IPv4Address.of("10.0.0.6"))
				||ipv44.getDestinationAddress().equals(IPv4Address.of("10.0.0.6"))))
		logger.info("from general ip {} {}", ipv44.getSourceAddress(), ipv44.getDestinationAddress());
		}
		MacAddress hostMac = MacAddress.of(sw.getId());
		Command ret = Command.STOP;
		//learn mac to port mapping
		OFPort input_port = (msg.getVersion().compareTo(OFVersion.OF_12) < 0 ? msg.getInPort() : msg.getMatch().get(MatchField.IN_PORT));
		
		macToPort.put(eth.getSourceMACAddress(), input_port);
		// logger.info("mac to port {}",macToPort.toString());
		Match match = _baadalUtils.createMatchFromPacket(sw, input_port ,cntx);
		// logger.info("original match of the packet {} {}", input_port.toString() ,match.toString());
		List<OFAction> actions = new ArrayList<OFAction>();
		VlanVid vlanId = VlanVid.ofVlan(eth.getVlanID()); 
		// change to initialization
		OFPort output_port = null; 
		VlanVid outVlanTag = null;
		int host_index = dpid_hosts.indexOf(MacAddress.of(sw.getId())); 

		if (eth.getEtherType() == EthType.ARP)
		{
			return Command.CONTINUE;
		}

		else if (eth.getEtherType() == EthType.IPv6)
		{
			_baadalUtils.doDropFlow(sw, msg, cntx, match);
			ret = Command.STOP;
		}
		
		else
		{
			if(macToPort.get(eth.getDestinationMACAddress()) == null)
			{
				_baadalUtils.doFlood(sw, msg, cntx, match);
				//logger.info("port not known for mac {}", eth.getDestinationMACAddress());
				ret = Command.STOP;
			}
			else
			{
				//logger.info("port KNOWN for mac {} and is {}", eth.getDestinationMACAddress(), macToPort.get(eth.getDestinationMACAddress()));
				output_port = macToPort.get(eth.getDestinationMACAddress());
				actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
				_baadalUtils.installAndSendout(sw, msg, cntx, match, actions);
				ret = Command.STOP;
			}
		}
		
		return ret;
	}
}
