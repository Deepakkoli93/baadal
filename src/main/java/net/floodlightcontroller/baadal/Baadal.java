package net.floodlightcontroller.baadal;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxmVlanVid;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.learningswitch.LearningSwitch;
import net.floodlightcontroller.mactracker.MACTracker;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.DHCP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.IPv6;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.routing.ForwardingBase;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.util.OFMessageDamper;

public class Baadal implements IFloodlightModule, IOFMessageListener {
	protected IFloodlightProviderService floodlightProvider;
	private static final short APP_ID = 99;
	protected static Logger logger;
	
	// taken from forwarding class
	protected static ITopologyService topologyService; //to get a list of ports that can send broadcast packets
	protected static OFMessageDamper messageDamper; // to write to switch
	static {
		AppCookie.registerApp(APP_ID, "Baadal");
	}

	// protected OFPort LOCAL = 1;
	// protected short TRUNK = 1;
	List<Map<OFPort, List<VlanVid> > > portToTag = new ArrayList< Map<OFPort, List<VlanVid> > >();
	//Map<MacAddress, OFPort> macToPort = new HashMap<MacAddress, OFPort>();
	Map<MacAddress, VlanVid> macToTag = new HashMap<MacAddress, VlanVid>(); //need to initialize it with central switch's mac with value 0
	MacAddress central_switch_mac = MacAddress.of("16:87:82:b3:a4:4d");
	MacAddress dpid_nat_br = MacAddress.of("52:52:00:01:15:03");
	MacAddress dpid_controller_br = MacAddress.of("52:52:00:01:15:02");
	List<MacAddress> dpid_hosts = new ArrayList<MacAddress>();
	Map<IPv4Address, MacAddress> ipToMac = new HashMap<IPv4Address, MacAddress> ();
	Map<MacAddress, VlanVid> mac2Tag = new HashMap<MacAddress, VlanVid>();
	
	protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
	protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms
	
	protected baadalUtils bu;
	protected baadalHost bh1, bh2;
	protected baadalGeneral bg;
	


	
	
	protected Command processPacketIn(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
//		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
//				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
//		if(!dpid_hosts.contains(MacAddress.of(sw.getId())))
//			return Command.CONTINUE;
//		if(MacAddress.of(sw.getId()).equals(MacAddress.of("52:52:00:01:15:07")))
//			return Command.CONTINUE;
//		Command ret = Command.STOP;
//		//learn mac to port mapping
//		OFPort input_port = (msg.getVersion().compareTo(OFVersion.OF_12) < 0 ? msg.getInPort() : msg.getMatch().get(MatchField.IN_PORT));
//		
//		macToPort.put(eth.getSourceMACAddress(), input_port);
//		// logger.info("mac to port {}",macToPort.toString());
//		Match match = createMatchFromPacket(sw, input_port ,cntx);
//		// logger.info("original match of the packet {} {}", input_port.toString() ,match.toString());
//		List<OFAction> actions = new ArrayList<OFAction>();
//		VlanVid vlanId = VlanVid.ofVlan(eth.getVlanID()); 
//		// change to initialization
//		OFPort output_port = null; 
//		VlanVid outVlanTag = null;
//		int host_index = dpid_hosts.indexOf(MacAddress.of(sw.getId())); 
//		// String srcNetwork = macToGuid.get(eth.getSourceMACAddress());
//		// If the host is on an unknown network we deny it.
//		// We make exceptions for ARP and DHCP.
//		// We do not handle ARP packets
//		
////		if (eth.isBroadcast() || eth.isMulticast() || /*isDefaultGateway(eth) || */isDhcpPacket(eth)) {
////			ret = Command.CONTINUE;
////		} 
//		if (eth.getEtherType() == EthType.ARP)
//		{
//
//			Command ret1 = Command.CONTINUE;
//			ARP arp = (ARP) eth.getPayload();
//			MacAddress hostmac = MacAddress.of("52:52:00:01:15:06");
//			IPv4Address gateway1 = IPv4Address.of("10.0.4.1");
//			IPv4Address gateway2 = IPv4Address.of("10.0.2.1");
//			logger.info("details->{} target address-> {}",arp.toString(), arp.getTargetProtocolAddress().toString());
//			logger.info("ARP packet details -> {}",arp.toString());
//			logger.info("generate reply");
//			
//			// generate ARP reply
//			if(arp.getOpCode().equals(ARP.OP_REQUEST))
//			{
//				if(arp.getSenderProtocolAddress().equals(IPv4Address.of("10.0.4.25")) && arp.getTargetProtocolAddress().equals(IPv4Address.of("10.0.4.1")))
//				{
//					IPacket arpReply = new Ethernet()
//					.setSourceMACAddress(hostmac)
//					.setDestinationMACAddress(eth.getSourceMACAddress())
//					.setEtherType(EthType.ARP)
//					.setPriorityCode(eth.getPriorityCode())
//					.setPayload(
//							new ARP()
//							.setHardwareType(ARP.HW_TYPE_ETHERNET)
//							.setProtocolType(ARP.PROTO_TYPE_IP)
//							.setHardwareAddressLength((byte) 6)
//							.setProtocolAddressLength((byte) 4)
//							.setOpCode(ARP.OP_REPLY)
//							.setSenderHardwareAddress(hostmac)
//							.setSenderProtocolAddress(gateway1)
//							.setTargetHardwareAddress(arp.getSenderHardwareAddress())
//							.setTargetProtocolAddress(arp.getSenderProtocolAddress())
//							);
//				sendARPReply(arpReply, sw, OFPort.ZERO, input_port);
//					return Command.STOP;
//				};
//				if(arp.getSenderProtocolAddress().equals(IPv4Address.of("10.0.2.15")) && arp.getTargetProtocolAddress().equals(IPv4Address.of("10.0.2.1")))
//				{
//					IPacket arpReply = new Ethernet()
//					.setSourceMACAddress(hostmac)
//					.setDestinationMACAddress(eth.getSourceMACAddress())
//					.setEtherType(EthType.ARP)
//					.setPriorityCode(eth.getPriorityCode())
//					.setPayload(
//							new ARP()
//							.setHardwareType(ARP.HW_TYPE_ETHERNET)
//							.setProtocolType(ARP.PROTO_TYPE_IP)
//							.setHardwareAddressLength((byte) 6)
//							.setProtocolAddressLength((byte) 4)
//							.setOpCode(ARP.OP_REPLY)
//							.setSenderHardwareAddress(hostmac)
//							.setSenderProtocolAddress(gateway2)
//							.setTargetHardwareAddress(arp.getSenderHardwareAddress())
//							.setTargetProtocolAddress(arp.getSenderProtocolAddress())
//							);
//				sendARPReply(arpReply, sw, OFPort.ZERO, input_port);
//					return Command.STOP;
//				};
////			if(arp.getTargetProtocolAddress().equals(vm3ip))
////			{
////			IPacket arpReply = new Ethernet()
////				.setSourceMACAddress(vm1mac)
////				.setDestinationMACAddress(eth.getSourceMACAddress())
////				.setEtherType(EthType.ARP)
////				.setPriorityCode(eth.getPriorityCode())
////				.setPayload(
////						new ARP()
////						.setHardwareType(ARP.HW_TYPE_ETHERNET)
////						.setProtocolType(ARP.PROTO_TYPE_IP)
////						.setHardwareAddressLength((byte) 6)
////						.setProtocolAddressLength((byte) 4)
////						.setOpCode(ARP.OP_REPLY)
////						.setSenderHardwareAddress(vm3mac)
////						.setSenderProtocolAddress(vm3ip)
////						.setTargetHardwareAddress(arp.getSenderHardwareAddress())
////						.setTargetProtocolAddress(arp.getSenderProtocolAddress())
////						);
////			sendARPReply(arpReply, sw, OFPort.ZERO, input_port);
////			}
////			else if(arp.getTargetProtocolAddress().equals(vm4ip))
////			{
////				IPacket arpReply = new Ethernet()
////				.setSourceMACAddress(vm2mac)
////				.setDestinationMACAddress(eth.getSourceMACAddress())
////				.setEtherType(EthType.ARP)
////				.setPriorityCode(eth.getPriorityCode())
////				.setPayload(
////						new ARP()
////						.setHardwareType(ARP.HW_TYPE_ETHERNET)
////						.setProtocolType(ARP.PROTO_TYPE_IP)
////						.setHardwareAddressLength((byte) 6)
////						.setProtocolAddressLength((byte) 4)
////						.setOpCode(ARP.OP_REPLY)
////						.setSenderHardwareAddress(vm4mac)
////						.setSenderProtocolAddress(vm4ip)
////						.setTargetHardwareAddress(arp.getSenderHardwareAddress())
////						.setTargetProtocolAddress(arp.getSenderProtocolAddress())
////						);
////			sendARPReply(arpReply, sw, OFPort.ZERO, input_port);
////			}
//			}
//			// if it is a reply and target mac addr is that of host then save the port
//			
//			else if (arp.getOpCode().equals(ARP.OP_REPLY))
//			{
//				logger.info("arp replies : {}", arp);
//				ipToMac.put(arp.getSenderProtocolAddress(), arp.getSenderHardwareAddress());
//
//			}
//			return ret1;
//			
//		}
//
//		else if (eth.getEtherType() == EthType.IPv6)
//		{
//			doDropFlow(sw, msg, cntx, match);
//			ret = Command.STOP;
//		}
//		
//		else if (input_port == OFPort.of(LOCAL)) {
////			logger.info("coming from local port");
////			logger.info("Datapath id of switch {}", sw.getId().toString());
////			Match m = createMatchFromPacket(sw, input_port, cntx);
////			logger.info("Packet details {}",m.toString());
//			macToTag.put(eth.getSourceMACAddress(),vlanId);
//			if(eth.isBroadcast() || eth.isMulticast())
//			{
//				doFlood(sw, msg, cntx, match);
//				ret = Command.STOP; // maybe drop this packet?
//			}
//			
//			else
//			{				
//				if(macToPort.get(eth.getDestinationMACAddress()) != null)
//				{
//					output_port = macToPort.get(eth.getDestinationMACAddress());
//					if(output_port == OFPort.of(TRUNK))
//					{
//						// if the tag is known
//						if(macToTag.get(eth.getDestinationMACAddress()) != null)
//						{
//							outVlanTag = macToTag.get(eth.getDestinationMACAddress());
//							
//							if(outVlanTag.getVlan() == 0)
//							{
//								// not sure why Integer.MAX_VALUE
//								
//								actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
//								installAndSendout(sw, msg, cntx, match, actions);
//								// logger.info("Adding flow, packet is tagged with zero {} {}", match.toString(), actions.toString());
//								ret = Command.STOP;
//							}
//							
//							else
//							{
//								
//								actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
//								//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag));
//								OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
//								actions.add(sw.getOFFactory().actions().setField(vlan));
//								actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
//								installAndSendout(sw, msg, cntx, match, actions);
//								ret = Command.STOP;
//							}
//						}
//						
//						// else if the tag is known
//						else
//						{
//							logger.info("The tag is NOT known");
//							actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
//							installAndSendout(sw, msg, cntx, match, actions);
//							ret = Command.STOP;
//						}
//					}
//					
//					// else if the port is LOCAL
//					else
//					{
//						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
//						installAndSendout(sw, msg, cntx, match, actions);
//						ret = Command.STOP;
//					}
//				}
//				
//				// else if the outport is not known
//				else
//				{
//					// output_port = OFPort.FLOOD;
//					// actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
//					// installAndSendout(sw, msg, cntx, match, actions);
//					logger.info("output port not known, flooding!");
//					doFlood(sw, msg, cntx, match, actions);
//					ret = Command.STOP;
//				}
//					
//			}
//		} 
//		
//		// else if in port is TRUNK
//		else if (input_port == OFPort.of(TRUNK))
//		{
//			//logger.info("coming from trunk port, Datapath id of switch {}", sw.getId().toString());
//			Match m = createMatchFromPacket(sw, input_port, cntx);
//			// logger.info("Packet details {}",m.toString());
//			// IPv4 ipv4 = (IPv4) eth.getPayload();
//			// logger.info("Packet type {}", eth.getEtherType());
//			// if packet is broadcast
//			if(eth.isBroadcast())
//			{
//				if(vlanId.getVlan() == 0) // if untagged
//				{
////					output_port = OFPort.FLOOD;
////					actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
////					installAndSendout(sw, msg, cntx, match, actions);
//					doFlood(sw, msg, cntx, match, actions);
//					ret = Command.STOP;
//				}
//				else // tagged
//				{
//					// strip the vlan tag to send out of access ports in vlan
//					actions.add(sw.getOFFactory().actions().popVlan());
////					output_port = OFPort.FLOOD;
////					actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
////					installAndSendout(sw, msg, cntx, match, actions);
//					doFlood(sw, msg, cntx, match, actions);
//					ret = Command.STOP;
//				}
//			}
//			
//			// else if packet is multicast
//			else if (eth.isMulticast())
//			{
//				match = createMatchFromPacket(sw, input_port, cntx);
//				
//				if(vlanId.getVlan() == 0) // is untagged
//				{
//					doFlood(sw, msg, cntx, match, actions);
//					ret = Command.STOP;
//				}
//				else // is tagged
//				{
//					actions.add(sw.getOFFactory().actions().popVlan());
//					doFlood(sw, msg, cntx, match, actions);
//					ret = Command.STOP;
//				}
//			}
//			
//			// if packet is unicast
//			else
//			{
//				// my_match.dl_src = packet.src
//				if(macToPort.get(eth.getDestinationMACAddress()) != null)
//				{
//					output_port = macToPort.get(eth.getDestinationMACAddress());
//					if(vlanId.getVlan() == 0) // if untagged
//					{
//						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
//						installAndSendout(sw, msg, cntx, match, actions);
//						//logger.info("At trunk, Adding flow, packet is tagged with zero {} {}", match.toString(), actions.toString());
//						ret = Command.STOP;
//					}
//					else // tagged
//					{
//						// strip the vlan tag
//						actions.add(sw.getOFFactory().actions().popVlan());
//						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
//						installAndSendout(sw, msg, cntx, match, actions);
//						ret = Command.STOP;
//					}
//				}
//				else //output port unknown
//				{
//					if(vlanId.getVlan() == 0) // if tagged
//					{
//						//flood and install flow
//						doFlood(sw, msg, cntx, match, actions);
//						ret = Command.STOP;
//					}
//					else // untagged
//					{
//						// find ports in vlan "out_vlan_tag"
//						List<OFPort> ports = find_tagToPort(vlanId, host_index);
//						ports.remove(OFPort.of(TRUNK));
//						
//						// strip the vlan tag
//						actions.add(sw.getOFFactory().actions().popVlan());
//						
//						// adding access ports in the vlan to out port list
//						for(OFPort port : ports)
//							actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
//						
//						actions.add(sw.getOFFactory().actions().output(OFPort.of(LOCAL), Integer.MAX_VALUE));
//						installAndSendout(sw, msg, cntx, match, actions);
//						ret = Command.STOP;
//					}
//				}
//			}
//		}
//		else //inport is an access port
//		{
//			// macToTag global dict; learnt only when packets ingress from ACCESS port
//			logger.info("host_index="+host_index+"input_port"+input_port+"src mac addr"+eth.getSourceMACAddress());			
//			macToTag.put(eth.getSourceMACAddress(), portToTag.get(host_index).get(input_port).get(0));
//			outVlanTag = portToTag.get(host_index).get(input_port).get(0);
//			
//			// if broadcast
//			if(eth.isBroadcast())
//			{
//				// find the host
//				host_index = dpid_hosts.indexOf(MacAddress.of(sw.getId()));
//				
//				// find ports in the vlan "out_vlan_tag"
//				List<OFPort> ports = find_tagToPort(outVlanTag, host_index);
//				
//				actions.add(sw.getOFFactory().actions().output(OFPort.of(LOCAL), Integer.MAX_VALUE));
//				// adding access ports in the vlan to out port list
//				for(OFPort port : ports)
//					actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
//				
//				// push vlan tag
//				actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
//				//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag));
//				OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
//				actions.add(sw.getOFFactory().actions().setField(vlan));
//				
//				// add trunk port in output too
//				actions.add(sw.getOFFactory().actions().output(OFPort.of(TRUNK), Integer.MAX_VALUE));
//				
//				installAndSendout(sw, msg, cntx, match, actions);
//				ret = Command.STOP;
//			}
//			
//			// else if multicast
//			else if(eth.isMulticast())
//			{
//				match = createMatchFromPacket(sw, input_port, cntx);
//				
//				// find the host
//				host_index = dpid_hosts.indexOf(MacAddress.of(sw.getId()));
//				
//				// find ports in the vlan "out_vlan_tag"
//				List<OFPort> ports = find_tagToPort(outVlanTag, host_index);
//				
//				actions.add(sw.getOFFactory().actions().output(OFPort.of(LOCAL), Integer.MAX_VALUE));
//				// adding access ports in the vlan to out port list
//				for(OFPort port : ports)
//					actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
//				
//				// push vlan tag
//				actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
//				//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag));
//				OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
//				actions.add(sw.getOFFactory().actions().setField(vlan));
//				
//				// add trunk port in output too
//				actions.add(sw.getOFFactory().actions().output(OFPort.of(TRUNK), Integer.MAX_VALUE));
//				
//				installAndSendout(sw, msg, cntx, match, actions);
//				ret = Command.STOP;
//			}
//			
//			else //unicast
//			{
//				IPv4 ipv4 = (IPv4) eth.getPayload();
//				
//				// if dest mac address is of host
//				// and dest ip address if not of host then act as router and change destination mac addresses
//				if(!ipv4.getDestinationAddress().equals(IPv4Address.of("10.0.0.6")) && eth.getDestinationMACAddress().equals(MacAddress.of("52:52:00:01:15:06")))
//				{
////					if(ipv4.getSourceAddress().equals(IPv4Address.of("10.0.4.25")) && ipv4.getDestinationAddress().equals(IPv4Address.of("10.0.2.15")))
////					{
////						// do this from ip to mac table
////						eth.setDestinationMACAddress(MacAddress.of("a2:00:00:e8:30:77"));
////					    eth.setSourceMACAddress(MacAddress.of("52:52:00:01:15:06"));	
////					}
////					else if(ipv4.getSourceAddress().equals(IPv4Address.of("10.0.2.15")) && ipv4.getDestinationAddress().equals(IPv4Address.of("10.0.4.25")))
////					{
////						eth.setDestinationMACAddress(MacAddress.of("a2:00:00:79:3d:56"));
////					    eth.setSourceMACAddress(MacAddress.of("52:52:00:01:15:06"));	
////					}
//					logger.info("iptomac : {}", ipToMac);
//					// mac address is not known then send ARP request
//					if(ipToMac.get(ipv4.getDestinationAddress()) == null)
//					{
//						IPacket arpRequest = new Ethernet()
//						.setSourceMACAddress(MacAddress.of("52:52:00:01:15:06"))
//						.setDestinationMACAddress(MacAddress.of("ff:ff:ff:ff:ff:ff"))
//						.setEtherType(EthType.ARP)
//						.setPayload(
//								new ARP()
//								.setHardwareType(ARP.HW_TYPE_ETHERNET)
//								.setProtocolType(ARP.PROTO_TYPE_IP)
//								.setHardwareAddressLength((byte) 6)
//								.setProtocolAddressLength((byte) 4)
//								.setOpCode(ARP.OP_REQUEST)
//								.setSenderHardwareAddress(MacAddress.of("52:52:00:01:15:99"))  // an unassigned mac id that it generates a PACKET_IN
//								.setSenderProtocolAddress(IPv4Address.of("10.0.0.6"))
//								.setTargetHardwareAddress(MacAddress.of("00:00:00:00:00:00"))
//								.setTargetProtocolAddress(ipv4.getDestinationAddress())
//								);
//						sendARPRequest(arpRequest, sw, OFPort.ZERO);
//	
//						//sleep while wating for arp reply
//						try {
//						    //TimeUnit.NANOSECONDS.sleep(100);
//						    //TimeUnit.MICROSECONDS.sleep(100);
//						    TimeUnit.MILLISECONDS.sleep(100);
//						   } catch (InterruptedException e) {
//						    logger.info("Error in sleeping : "+e);
//						   }
//					}
//					
//					if(ipToMac.get(ipv4.getDestinationAddress()) == null)
//					{
//						// if still didn't resolve the mac address
//						return Command.STOP;
//					}
//					else
//					{
//						// change the ethernet frame to reflect the next hop mac address 
//						eth.setDestinationMACAddress(ipToMac.get(ipv4.getDestinationAddress()));
//					    eth.setSourceMACAddress(MacAddress.of("52:52:00:01:15:06"));
//					}
//					
//					// if output port is not known 
//					if(macToPort.get(eth.getDestinationMACAddress()) == null)
//					{
//						IPacket arpRequest = new Ethernet()
//						.setSourceMACAddress(MacAddress.of("52:52:00:01:15:06"))
//						.setDestinationMACAddress(MacAddress.of("ff:ff:ff:ff:ff:ff"))
//						.setEtherType(EthType.ARP)
//						.setPayload(
//								new ARP()
//								.setHardwareType(ARP.HW_TYPE_ETHERNET)
//								.setProtocolType(ARP.PROTO_TYPE_IP)
//								.setHardwareAddressLength((byte) 6)
//								.setProtocolAddressLength((byte) 4)
//								.setOpCode(ARP.OP_REQUEST)
//								.setSenderHardwareAddress(MacAddress.of("52:52:00:01:15:99"))  // an unassigned mac id that it generates a PACKET_IN
//								.setSenderProtocolAddress(IPv4Address.of("10.0.0.6"))
//								.setTargetHardwareAddress(MacAddress.of("00:00:00:00:00:00"))
//								.setTargetProtocolAddress(ipv4.getDestinationAddress())
//								);
//						sendARPRequest(arpRequest, sw, OFPort.ZERO);
//	
//						//sleep while wating for arp reply
//						try {
//						    //TimeUnit.NANOSECONDS.sleep(100);
//						    //TimeUnit.MICROSECONDS.sleep(100);
//						    TimeUnit.MILLISECONDS.sleep(100);
//						   } catch (InterruptedException e) {
//						    logger.info("Error in sleeping : "+e);
//						   }
//					}
//					
//					
//					
//				}
//				
//
//				
//				logger.info("look here dest {}, src {}", ipv4.getDestinationAddress(), ipv4.getSourceAddress());
//				logger.info("look here whole packet eth {} and ipv4 {}", eth.toString(), ipv4.toString());
//				logger.info("mactoport {}", macToPort.toString());
//				
//				if(macToPort.get(eth.getDestinationMACAddress()) != null)
//				{
//					logger.info("Packet coming from access port, outport is known and is {} for mac address {}", 
//					macToPort.get(eth.getDestinationMACAddress()), eth.getDestinationMACAddress());
//					logger.info("mac to port -> {}",macToPort.toString());
//					output_port = macToPort.get(eth.getDestinationMACAddress());
//					
//					if(output_port.getPortNumber() == TRUNK)
//					{
//						// push vlan tag
//						actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
//						//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag));
//						OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
//						actions.add(sw.getOFFactory().actions().setField(vlan));
//						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
//						installAndSendout(sw, msg, cntx, match, actions, eth);
//						ret = Command.STOP;
//					}
//					else
//					{
//						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
//						installAndSendout(sw, msg, cntx, match, actions, eth);
//						ret = Command.STOP;
//					}
//				}
//				
//				else //output port is unknown
//				{
//					logger.info("Packet coming from access port, outport is NOT known");
//					// find the host
//					host_index = dpid_hosts.indexOf(MacAddress.of(sw.getId()));
//					
//					// find ports in the vlan "out_vlan_tag"
//					List<OFPort> ports = find_tagToPort(outVlanTag, host_index);
//					actions.add(sw.getOFFactory().actions().output(OFPort.of(LOCAL), Integer.MAX_VALUE));
//					// adding access ports in the vlan to out port list
//					for(OFPort port : ports)
//						actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
//					
//					// push vlan tag
//					actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
//					//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag));
//					OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
//					actions.add(sw.getOFFactory().actions().setField(vlan));
//					
//					// add trunk port in output too
//					//actions.add(sw.getOFFactory().actions().output(OFPort.of(TRUNK), Integer.MAX_VALUE));
//					
//					installAndSendout(sw, msg, cntx, match, actions);
//					ret = Command.STOP;
//				}
//			}
//			
//		}
////		
//		if (logger.isTraceEnabled())
//			logger.trace("Results for flow between {} and {} is {}",
//					new Object[] {eth.getSourceMACAddress(), eth.getDestinationMACAddress(), ret});
//		/*
//		 * TODO - figure out how to still detect gateways while using
//		 * drop mods
//        if (ret == Command.STOP) {
//            if (!(eth.getPayload() instanceof ARP))
//                doDropFlow(sw, msg, cntx);
//        }
//		 */
//		return ret;
		MacAddress switchMac = MacAddress.of(sw.getId());

		if(switchMac.equals(MacAddress.of("52:52:00:01:15:06")))
			return bh1.processPacketIn(sw, msg, cntx);
		else if  (switchMac.equals(MacAddress.of("52:52:00:01:15:07")))
			return bh2.processPacketIn(sw, msg, cntx);
		else if (switchMac.equals(MacAddress.of("16:87:82:b3:a4:4d")))
			return bg.processPacketIn(sw, msg, cntx);
		else
			return Command.CONTINUE;
		
	}
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return Baadal.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// Link discovery should go before us so we don't block LLDPs
		return (type.equals(OFType.PACKET_IN) &&
				(name.equals("linkdiscovery") || (name.equals("devicemanager"))));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// We need to go before forwarding
		return (type.equals(OFType.PACKET_IN) && name.equals("forwarding"));
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		switch (msg.getType()) { 
		case PACKET_IN:
			return processPacketIn(sw, (OFPacketIn)msg, cntx);
		default:
			break;
		}
		logger.warn("Received unexpected message {}", msg);
		return Command.CONTINUE;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
		        new ArrayList<Class<? extends IFloodlightService>>();
		    l.add(IFloodlightProviderService.class);
		    l.add(ITopologyService.class);
		    return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
				EnumSet.of(OFType.FLOW_MOD),
				OFMESSAGE_DAMPER_TIMEOUT);
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		logger = (Logger) LoggerFactory.getLogger(Baadal.class);
		topologyService = context.getServiceImpl(ITopologyService.class);
		macToTag.put(central_switch_mac, VlanVid.ofVlan(0));
		dpid_hosts.add(0,MacAddress.of("52:52:00:01:15:06"));
		dpid_hosts.add(1,MacAddress.of("52:52:00:01:15:07"));
		// initializing port to tag
		Map<OFPort, List<VlanVid> > portToTag1 = new HashMap<OFPort, List<VlanVid> >();
		for(int i=0; i<21; i++)
		{
			if(i == 0)
			{
				List<VlanVid> tags = new ArrayList<VlanVid>();
				tags.add(VlanVid.ofVlan(0));
				portToTag1.put(OFPort.of((short) 65534), tags);
			}
			
			else if (i == 1)
			{
				List<VlanVid> tags = new ArrayList<VlanVid>();
				for(int j=0; j<4095; j++)
					tags.add(VlanVid.ofVlan(j));
				portToTag1.put(OFPort.of(1), tags);
			}
			
			else
			{
				List<VlanVid> tags = new ArrayList<VlanVid>();
				tags.add(VlanVid.ofVlan(2));
				portToTag1.put(OFPort.of(i), tags);
			}
		}
		
		portToTag.add(0,portToTag1);
		portToTag.add(1,portToTag1);
		
		// initialize mac to tag mapping
		mac2Tag.put(MacAddress.of("a2:00:00:e5:7f:6f"), VlanVid.ofVlan(4));
		mac2Tag.put(MacAddress.of("a2:00:00:a3:90:5c"), VlanVid.ofVlan(2));
		mac2Tag.put(MacAddress.of("a2:00:00:6c:f8:ec"), VlanVid.ofVlan(4));
		mac2Tag.put(MacAddress.of("a2:00:00:79:3d:56"), VlanVid.ofVlan(4));
		mac2Tag.put(MacAddress.of("a2:00:00:e8:30:77"), VlanVid.ofVlan(2));
		mac2Tag.put(MacAddress.of("a2:00:00:fc:a9:8b"), VlanVid.ofVlan(2));
		mac2Tag.put(MacAddress.of("a2:00:00:94:e0:de"), VlanVid.ofVlan(4));
		
		// initialize baadalUtils;
		bu = new baadalUtils(topologyService, messageDamper, APP_ID, logger);
		
		// initialize baadalHosts
		bh1 = new baadalHost(logger, bu, dpid_hosts, macToTag, portToTag, IPv4Address.of("10.0.0.6"), mac2Tag);
		bh2 = new baadalHost(logger, bu, dpid_hosts, macToTag, portToTag, IPv4Address.of("10.0.0.7"), mac2Tag);
		
		//initialize centrsal bridge
		bg = new baadalGeneral(logger, bu, dpid_hosts, macToTag, portToTag, IPv4Address.of("10.0.0.1"));
		

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		

	}

}
