package net.floodlightcontroller.baadal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
import org.projectfloodlight.openflow.protocol.oxm.OFOxmEthDst;
import org.projectfloodlight.openflow.protocol.oxm.OFOxmEthSrc;
import org.projectfloodlight.openflow.protocol.oxm.OFOxmVlanVid;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.VlanVid;

//import net.floodlightcontroller.baadal._baadalUtils.*;

public class baadalHost {
	protected static Logger logger;
	private Map<MacAddress, OFPort> macToPort;
	Map<IPv4Address, MacAddress> ipToMac;
	baadalUtils _baadalUtils;
	List<MacAddress> dpid_hosts;
	Map<MacAddress, VlanVid> macToTag;
	List<Map<OFPort, List<VlanVid> > > portToTag;
	IPv4Address hostip;
	Map<IPv4Address, VlanVid> ipToTag; 
	boolean ENABLE_INTER_VLAN_ROUTING;
	ConcurrentHashMap<IPv4Address, ConcurrentHashMap<IPv4Address, Boolean> > interVmPolicy;
	List<IPv4Address> gateways;
	
	public baadalHost(Logger _logger, baadalUtils bu, List<MacAddress> _dpid_hosts, Map<MacAddress, VlanVid> _macToTag, 
			List<Map<OFPort, List<VlanVid> > > _portToTag, IPv4Address _hostip, Map<IPv4Address, VlanVid> _ipToTag,
			ConcurrentHashMap<IPv4Address, ConcurrentHashMap<IPv4Address, Boolean> > _interVmPolicy,
			List<IPv4Address> _gateways){
		logger = _logger;
		macToPort = new HashMap<MacAddress, OFPort>();
		ipToMac = new HashMap<IPv4Address, MacAddress> ();
		_baadalUtils = bu;
		dpid_hosts = _dpid_hosts;
		macToTag = _macToTag;
		portToTag = _portToTag;
		hostip = _hostip;
		ipToTag = _ipToTag;
		ENABLE_INTER_VLAN_ROUTING = false;
		interVmPolicy = _interVmPolicy;
		gateways = _gateways;
	}
	
	public void setIPToTag(Map<IPv4Address, VlanVid> _ipToTag)
	{
		ipToTag = _ipToTag;
	}
	
	public void setInterVmPolicy(ConcurrentHashMap<IPv4Address, ConcurrentHashMap<IPv4Address, Boolean> > _interVmPolicy)
	{
		interVmPolicy = _interVmPolicy;
	}
	
	public void clearCache()
	{
		ipToMac.clear();
		macToPort.clear();
	}
	
	protected Command processPacketIn(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

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

			Command ret1 = Command.CONTINUE;
			ARP arp = (ARP) eth.getPayload();
			//logger.info("details->{} target address-> {}",arp.toString(), arp.getTargetProtocolAddress().toString());
			//logger.info("ARP packet details -> {}",arp.toString());
			//logger.info("generate reply");
			
			// generate ARP reply
			if(arp.getOpCode().equals(ARP.OP_REQUEST))
			{
//				if(arp.getTargetProtocolAddress().equals(IPv4Address.of("10.0.4.1")))
//				{
//
//				_baadalUtils.sendARPReply(sw, OFPort.ZERO, input_port, hostMac, eth.getSourceMACAddress(), eth.getPriorityCode(),
//						hostMac, gateway1, arp.getSenderHardwareAddress(), arp.getSenderProtocolAddress());
//					return Command.STOP;
//				};
//				if(arp.getTargetProtocolAddress().equals(IPv4Address.of("10.0.2.1")))
//				{
//
//				_baadalUtils.sendARPReply(sw, OFPort.ZERO, input_port, hostMac, eth.getSourceMACAddress(), eth.getPriorityCode(),
//						hostMac, gateway2, arp.getSenderHardwareAddress(), arp.getSenderProtocolAddress());
//					return Command.STOP;
//				};
				int gatewayIndex = -1;
				if((gatewayIndex=gateways.indexOf(arp.getTargetProtocolAddress())) != -1)
				{
					logger.info("gateways index{}", gatewayIndex);
					_baadalUtils.sendARPReply(sw, OFPort.ZERO, input_port, hostMac, eth.getSourceMACAddress(), eth.getPriorityCode(),
							hostMac, gateways.get(gatewayIndex), arp.getSenderHardwareAddress(), arp.getSenderProtocolAddress());
						return Command.STOP; 
				}

			}
			
			
			else if (arp.getOpCode().equals(ARP.OP_REPLY))
			{
				logger.info("arp replies : {}", arp);
				ipToMac.put(arp.getSenderProtocolAddress(), arp.getSenderHardwareAddress());

			}
			return ret1;
			
		}

		else if (eth.getEtherType() == EthType.IPv6)
		{
			_baadalUtils.doDropFlow(sw, msg, cntx, match);
			ret = Command.STOP;
		}
		
		else if (input_port == OFPort.of(_baadalUtils.LOCAL)) {
//			logger.info("coming from local port");
//			logger.info("Datapath id of switch {}", sw.getId().toString());
//			Match m = createMatchFromPacket(sw, input_port, cntx);
//			logger.info("Packet details {}",m.toString());
			macToTag.put(eth.getSourceMACAddress(),vlanId);
			if(eth.isBroadcast() || eth.isMulticast())
			{
				_baadalUtils.doFlood(sw, msg, cntx, match);
				ret = Command.STOP; // maybe drop this packet?
			}
			
			else
			{	
				// hack to change packet header for 99 mac address
				IPv4 ipv4 = (IPv4)eth.getPayload();
				if(eth.getDestinationMACAddress().equals(MacAddress.of("52:52:00:01:15:99")))
				{
					if(ipv4.getDestinationAddress().equals(IPv4Address.of("10.0.0.6")))
					{
						OFOxmEthDst dstMac = sw.getOFFactory().oxms().ethDst(MacAddress.of("52:52:00:01:15:06"));
						actions.add(sw.getOFFactory().actions().setField(dstMac));
					}
					else if(ipv4.getDestinationAddress().equals(IPv4Address.of("10.0.0.7")))
					{
						OFOxmEthDst dstMac = sw.getOFFactory().oxms().ethDst(MacAddress.of("52:52:00:01:15:07"));
						actions.add(sw.getOFFactory().actions().setField(dstMac));
					}
				}

				// if packet comes from local port then always route using IP
				if(ipToMac.get(ipv4.getDestinationAddress()) == null)
				{

					_baadalUtils.sendARPRequest(sw, OFPort.ZERO, hostMac, MacAddress.of("52:52:00:01:15:99"), hostip,
							ipv4.getDestinationAddress());
					//sleep while wating for arp reply
					try {
					    //TimeUnit.NANOSECONDS.sleep(100);
					    //TimeUnit.MICROSECONDS.sleep(100);
					    TimeUnit.MILLISECONDS.sleep(100);
					   } catch (InterruptedException e) {
					    logger.info("Error in sleeping : "+e);
					   }
				}
				
				if(ipToMac.get(ipv4.getDestinationAddress()) == null)
				{
					// if still didn't resolve the mac address
					return Command.STOP;
				}
				else
				{
					// change the ethernet frame to reflect the next hop mac address 
					eth.setDestinationMACAddress(ipToMac.get(ipv4.getDestinationAddress()));
				    OFOxmEthDst dstMac = sw.getOFFactory().oxms().ethDst(ipToMac.get(ipv4.getDestinationAddress()));
				    actions.add(sw.getOFFactory().actions().setField(dstMac));			
				    
				}
				
				// by now we should have the output port
				if(macToPort.get(eth.getDestinationMACAddress()) != null)
				{				
					output_port = macToPort.get(eth.getDestinationMACAddress());
					actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
					_baadalUtils.installAndSendout(sw, msg, cntx, match, actions, eth);
					ret = Command.STOP;					
				}
				// if still did not resolve then drop
				else
				{
					return Command.STOP;
				}
			}
		} 
		
		// else if in port is TRUNK
		else if (input_port == OFPort.of(_baadalUtils.TRUNK))
		{
			//logger.info("coming from trunk port, Datapath id of switch {}", sw.getId().toString());
			// Match m = _baadalUtils.createMatchFromPacket(sw, input_port, cntx);
			// logger.info("Packet details {}",m.toString());
			// IPv4 ipv4 = (IPv4) eth.getPayload();
			// logger.info("Packet type {}", eth.getEtherType());
			// if packet is broadcast
			if(eth.isBroadcast())
			{
				if(vlanId.getVlan() == 0) // if untagged
				{
//					output_port = OFPort.FLOOD;
//					actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
//					installAndSendout(sw, msg, cntx, match, actions);
					_baadalUtils.doFlood(sw, msg, cntx, match, actions);
					ret = Command.STOP;
				}
				else // tagged
				{
					// strip the vlan tag to send out of access ports in vlan
					actions.add(sw.getOFFactory().actions().popVlan());
//					output_port = OFPort.FLOOD;
//					actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
//					installAndSendout(sw, msg, cntx, match, actions);
					_baadalUtils.doFlood(sw, msg, cntx, match, actions);
					ret = Command.STOP;
				}
			}
			
			// else if packet is multicast
			else if (eth.isMulticast())
			{
				match = _baadalUtils.createMatchFromPacket(sw, input_port, cntx);
				
				if(vlanId.getVlan() == 0) // is untagged
				{
					_baadalUtils.doFlood(sw, msg, cntx, match, actions);
					ret = Command.STOP;
				}
				else // is tagged
				{
					actions.add(sw.getOFFactory().actions().popVlan());
					_baadalUtils.doFlood(sw, msg, cntx, match, actions);
					ret = Command.STOP;
				}
			}
			
			// if packet is unicast
			else
			{
				IPv4 ipv4 = (IPv4)eth.getPayload();
				// if outpot port is not known then find it out
				if(macToPort.get(eth.getDestinationMACAddress()) == null)
				{

					_baadalUtils.sendARPRequest(sw, OFPort.ZERO, hostMac, MacAddress.of("52:52:00:01:15:99"), hostip,
							ipv4.getDestinationAddress());

					//sleep while wating for arp reply
					try {
					    //TimeUnit.NANOSECONDS.sleep(100);
					    //TimeUnit.MICROSECONDS.sleep(100);
					    TimeUnit.MILLISECONDS.sleep(100);
					   } catch (InterruptedException e) {
					    logger.info("Error in sleeping : "+e);
					   }
				}
				
				if(macToPort.get(eth.getDestinationMACAddress()) == null)
				{
					// if still didn't resolve the mac address
					return Command.STOP;
				}
				// now we definitely have the output port
				else
				{
					output_port = macToPort.get(eth.getDestinationMACAddress());
					
					if(output_port.getPortNumber() == _baadalUtils.TRUNK || output_port.equals(OFPort.LOCAL))
					{
						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
						_baadalUtils.installAndSendout(sw, msg, cntx, match, actions);
						return Command.STOP;
					}
					else // outport is access port
					{
						if(vlanId.equals(VlanVid.ZERO)) //if untagged
						{
							actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
							_baadalUtils.installAndSendout(sw, msg, cntx, match, actions);
							ret = Command.STOP;
						}
						else // tagged
						{
							logger.info("decision here {}", _baadalUtils.getPolicy(interVmPolicy, ipv4.getSourceAddress(), ipv4.getDestinationAddress()));

							switch(_baadalUtils.getPolicy(interVmPolicy, ipv4.getSourceAddress(), ipv4.getDestinationAddress())){
							case ALLOW:
								actions.add(sw.getOFFactory().actions().popVlan());
								actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
								_baadalUtils.installAndSendout(sw, msg, cntx, match, actions, eth);
								ret = Command.STOP;
								break;
							case DISALLOW:
								_baadalUtils.doDropFlow(sw, msg, cntx, match);
								ret = Command.STOP;
								break;
							case DEFAULT:
								if(ENABLE_INTER_VLAN_ROUTING)
								{
									actions.add(sw.getOFFactory().actions().popVlan());
									actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
									_baadalUtils.installAndSendout(sw, msg, cntx, match, actions);
									ret = Command.STOP;
								}
								else //inter vlan routing is disabled
								{
									if(vlanId.equals(ipToTag.get(ipv4.getDestinationAddress()))) // if tag is same as that of destination
									{
										actions.add(sw.getOFFactory().actions().popVlan());
										actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
										_baadalUtils.installAndSendout(sw, msg, cntx, match, actions);
										ret = Command.STOP;
									}
									else // tag is different from that of destination
									{
										_baadalUtils.doDropFlow(sw, msg, cntx, match);
										ret = Command.STOP;
									}
								}
								break;
							default:
								logger.warn("Unexpected policy decision, dropping packet");
								return Command.STOP;
						  }
						}
					}
				}

			}
		}
		else //inport is an access port
		{
			IPv4 ipv4 = (IPv4)eth.getPayload();
			macToTag.put(eth.getSourceMACAddress(), portToTag.get(host_index).get(input_port).get(0));
			outVlanTag = ipToTag.get(ipv4.getSourceAddress());
			//logger.info("look at the vlan tag {}", outVlanTag);
			
			// if broadcast
			if(eth.isBroadcast())
			{
				// find the host
				host_index = dpid_hosts.indexOf(MacAddress.of(sw.getId()));
				
				// find ports in the vlan "out_vlan_tag"
				List<OFPort> ports = _baadalUtils.find_tagToPort(outVlanTag, host_index, portToTag);
				
				actions.add(sw.getOFFactory().actions().output(OFPort.of(_baadalUtils.LOCAL), Integer.MAX_VALUE));
				// adding access ports in the vlan to out port list
				for(OFPort port : ports)
					actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
				
				// push vlan tag
				actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
				//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag));
				OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
				actions.add(sw.getOFFactory().actions().setField(vlan));
				
				// add trunk port in output too
				actions.add(sw.getOFFactory().actions().output(OFPort.of(_baadalUtils.TRUNK), Integer.MAX_VALUE));
				
				_baadalUtils.installAndSendout(sw, msg, cntx, match, actions);
				ret = Command.STOP;
			}
			
			// else if multicast
			else if(eth.isMulticast())
			{
				match = _baadalUtils.createMatchFromPacket(sw, input_port, cntx);
				
				// find the host
				host_index = dpid_hosts.indexOf(MacAddress.of(sw.getId()));
				
				// find ports in the vlan "out_vlan_tag"
				List<OFPort> ports = _baadalUtils.find_tagToPort(outVlanTag, host_index, portToTag);
				
				actions.add(sw.getOFFactory().actions().output(OFPort.of(_baadalUtils.LOCAL), Integer.MAX_VALUE));
				// adding access ports in the vlan to out port list
				for(OFPort port : ports)
					actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
				
				// push vlan tag
				actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
				//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag));
				OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
				actions.add(sw.getOFFactory().actions().setField(vlan));
				
				// add trunk port in output too
				actions.add(sw.getOFFactory().actions().output(OFPort.of(_baadalUtils.TRUNK), Integer.MAX_VALUE));
				
				_baadalUtils.installAndSendout(sw, msg, cntx, match, actions);
				ret = Command.STOP;
			}
			
			else //unicast
			{
				
				//IPv4 ipv4 = (IPv4) eth.getPayload();
				logger.info("mactoport {}", macToPort);
				
				// if dest mac address is of host
				// and dest ip address if not of host then act as router and change destination mac addresses
				if(!ipv4.getDestinationAddress().equals(hostip) && eth.getDestinationMACAddress().equals(hostMac))
				{

					logger.info("iptomac : {}", ipToMac);
					// destination mac address is not known then send ARP request
					if(ipToMac.get(ipv4.getDestinationAddress()) == null)
					{

						_baadalUtils.sendARPRequest(sw, OFPort.ZERO, hostMac, MacAddress.of("52:52:00:01:15:99"), hostip,
								ipv4.getDestinationAddress());
	
						//sleep while wating for arp reply
						try {
						    //TimeUnit.NANOSECONDS.sleep(100);
						    //TimeUnit.MICROSECONDS.sleep(100);
						    TimeUnit.MILLISECONDS.sleep(100);
						   } catch (InterruptedException e) {
						    logger.info("Error in sleeping : "+e);
						   }
					}
					
					if(ipToMac.get(ipv4.getDestinationAddress()) == null)
					{
						// if still didn't resolve the mac address
						return Command.STOP;
					}
					else
					{
						// change the ethernet frame to reflect the next hop mac address 
						eth.setDestinationMACAddress(ipToMac.get(ipv4.getDestinationAddress()));
					    eth.setSourceMACAddress(hostMac);
					    // actions.add(sw.getOFFactory().actions().setDlDst(ipToMac.get(ipv4.getDestinationAddress())));
					    // actions.add(sw.getOFFactory().actions().setDlSrc(hostMac));
					    
					    
					    
					    OFOxmEthDst dstMac = sw.getOFFactory().oxms().ethDst(ipToMac.get(ipv4.getDestinationAddress()));
					    actions.add(sw.getOFFactory().actions().setField(dstMac));
					    
					    OFOxmEthSrc srcMac = sw.getOFFactory().oxms().ethSrc(hostMac);
					    actions.add(sw.getOFFactory().actions().setField(srcMac));
					    
					    
					    
					}
					
					
					// if output port is not known 
					if(macToPort.get(eth.getDestinationMACAddress()) == null)
					{

						_baadalUtils.sendARPRequest(sw, OFPort.ZERO, hostMac, MacAddress.of("52:52:00:01:15:99"), hostip,
								ipv4.getDestinationAddress());
	
						//sleep while wating for arp reply
						try {
						    //TimeUnit.NANOSECONDS.sleep(100);
						    //TimeUnit.MICROSECONDS.sleep(100);
						    TimeUnit.MILLISECONDS.sleep(100);
						   } catch (InterruptedException e) {
						    logger.info("Error in sleeping : "+e);
						   }
					}
					
					
					
				}
				

				// by now we should have the output port
				logger.info("look here dest {}, src {}", ipv4.getDestinationAddress(), ipv4.getSourceAddress());
				logger.info("look here whole packet eth {} and ipv4 {}", eth.toString(), ipv4.toString());
				logger.info("mactoport {}", macToPort.toString());
				
				if(macToPort.get(eth.getDestinationMACAddress()) != null)
				{				
					output_port = macToPort.get(eth.getDestinationMACAddress());
					
					if(output_port.getPortNumber() == _baadalUtils.TRUNK)
					{
						// get vlan tag
						// push vlan tag
						actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
						//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag)); this line causes an error, don't uncomment!
						OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
						actions.add(sw.getOFFactory().actions().setField(vlan));
						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
						_baadalUtils.installAndSendout(sw, msg, cntx, match, actions, eth);
						ret = Command.STOP;
					}
					else if(output_port.equals(OFPort.LOCAL))
					{
						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
						_baadalUtils.installAndSendout(sw, msg, cntx, match, actions, eth);
						ret = Command.STOP;
					}
					// output port is access port
					else
					{
						
						logger.info("decision here {}", _baadalUtils.getPolicy(interVmPolicy, ipv4.getSourceAddress(), ipv4.getDestinationAddress()));

						switch(_baadalUtils.getPolicy(interVmPolicy, ipv4.getSourceAddress(), ipv4.getDestinationAddress())){
						case ALLOW:
							actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
							_baadalUtils.installAndSendout(sw, msg, cntx, match, actions, eth);
							ret = Command.STOP;
							break;
						case DISALLOW:
							_baadalUtils.doDropFlow(sw, msg, cntx, match);
							ret = Command.STOP;
							break;
						case DEFAULT:
							if(ENABLE_INTER_VLAN_ROUTING)
							{
								actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
								_baadalUtils.installAndSendout(sw, msg, cntx, match, actions, eth);
								ret = Command.STOP;
							}
							else // inter-vlan routing is disabled
							{
								// if they are in same vlan the allow
								if(ipToTag.get(ipv4.getSourceAddress()).equals(ipToTag.get(ipv4.getDestinationAddress())))
								{
									actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
									_baadalUtils.installAndSendout(sw, msg, cntx, match, actions, eth);
									ret = Command.STOP;
								}
								else // not in same vlan, so drop
								{
									// logger.info("look at the changed match here -> {}", match);
									_baadalUtils.doDropFlow(sw, msg, cntx, match);
									ret = Command.STOP;
								}
							}
							break;
						default:
							logger.warn("Unexpected policy decision, dropping packet");
							return Command.STOP;
					  }
					}
				}
				
				// TODO: remove this else part because at this point the output port has been discovered, 
				// if it is discoveraable, drop the packet in thie else
				else //output port is unknown
				{
					logger.info("Packet coming from access port, outport is NOT known");
					// find the host
					host_index = dpid_hosts.indexOf(MacAddress.of(sw.getId()));
					
					// find ports in the vlan "out_vlan_tag"
					List<OFPort> ports = _baadalUtils.find_tagToPort(outVlanTag, host_index, portToTag);
					actions.add(sw.getOFFactory().actions().output(OFPort.of(_baadalUtils.LOCAL), Integer.MAX_VALUE));
					// adding access ports in the vlan to out port list
					for(OFPort port : ports)
						actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
					
					// push vlan tag
					actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
					//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag));
					OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
					actions.add(sw.getOFFactory().actions().setField(vlan));
					
					// add trunk port in output too
					//actions.add(sw.getOFFactory().actions().output(OFPort.of(TRUNK), Integer.MAX_VALUE));
					
					_baadalUtils.installAndSendout(sw, msg, cntx, match, actions);
					ret = Command.STOP;
				}
			}
			
		}
		
		if (logger.isTraceEnabled())
			logger.trace("Results for flow between {} and {} is {}",
					new Object[] {eth.getSourceMACAddress(), eth.getDestinationMACAddress(), ret});

		return ret;
	}
}
