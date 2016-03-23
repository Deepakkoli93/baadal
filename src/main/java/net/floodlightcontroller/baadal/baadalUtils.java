package net.floodlightcontroller.baadal;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.util.AppCookie;
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

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
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

import ch.qos.logback.classic.Logger;

public class baadalUtils {
	
	protected static Logger logger;
	


	public static int FLOWMOD_DEFAULT_IDLE_TIMEOUT = 15; // in seconds
	public static int FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	public static int FLOWMOD_DEFAULT_PRIORITY = 1; // 0 is the default table-miss flow in OF1.3+, so we need to use 1
	
	public static boolean FLOWMOD_DEFAULT_SET_SEND_FLOW_REM_FLAG = false;
	
	public static boolean FLOWMOD_DEFAULT_MATCH_VLAN = true;
	public static boolean FLOWMOD_DEFAULT_MATCH_MAC = true;
	public static boolean FLOWMOD_DEFAULT_MATCH_IP_ADDR = true;
	public static boolean FLOWMOD_DEFAULT_MATCH_TRANSPORT = true;

	public static final short FLOWMOD_DEFAULT_IDLE_TIMEOUT_CONSTANT = 5;
	public static final short FLOWMOD_DEFAULT_HARD_TIMEOUT_CONSTANT = 0;
	
	public static boolean FLOOD_ALL_ARP_PACKETS = false;
	
	public short LOCAL = (short) 65534; //baadal-br-int
	public short TRUNK = 1; //eth0
	
	protected static ITopologyService topologyService;
	protected static OFMessageDamper messageDamper ;
	private static short APP_ID;
	
	public static enum policyDecision{ ALLOW, DISALLOW, DEFAULT}
	
	public baadalUtils(ITopologyService _topologyService, OFMessageDamper _messageDamper, short _APP_ID, Logger _logger){
		topologyService = _topologyService;
		messageDamper = _messageDamper;
		APP_ID = _APP_ID;
		logger = _logger;
	}

	
	/**
	 * Writes a FlowMod to a switch that inserts a drop flow.
	 * @param sw The switch to write the FlowMod to.
	 * @param pi The corresponding OFPacketIn. Used to create the OFMatch structure.
	 * @param cntx The FloodlightContext that gets passed to the switch.
	 */
	 public void doDropFlow(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Match match) {
		if (logger.isTraceEnabled()) {
			logger.trace("doDropFlow pi={} srcSwitch={}",
					new Object[] { pi, sw });
		}

		if (sw == null) {
			logger.warn("Switch is null, not installing drop flowmod for PacketIn {}", pi);
			return;
		}

		// Create flow-mod based on packet-in and src-switch
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
		List<OFAction> actions = new ArrayList<OFAction>(); // no actions = drop
		U64 cookie = AppCookie.makeCookie(APP_ID, 0);
		fmb.setCookie(cookie)
		.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
		.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setMatch(match)
		.setActions(actions);

		if (logger.isTraceEnabled()) {
			logger.trace("write drop flow-mod srcSwitch={} match={} " +
					"pi={} flow-mod={}",
					new Object[] {sw, match, pi, fmb.build()});
		}
		sw.write(fmb.build());
		return;
	}
	
	
	/**
	 * Creates a OFPacketOut with the OFPacketIn data that is flooded on all ports unless
	 * writes a flood mod to flood packet at all ports
	 * the port is blocked, in which case the packet will be dropped.
	 * @param sw The switch that receives the OFPacketIn
	 * @param pi The OFPacketIn that came to the switch
	 * @param cntx The FloodlightContext associated with this OFPacketIn
	 */
	
	 public void doFlood(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Match match) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		// Set Action to flood
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		List<OFAction> actions = new ArrayList<OFAction>();
		Set<OFPort> broadcastPorts = topologyService.getSwitchBroadcastPorts(sw.getId());

		if (broadcastPorts == null) {
			logger.debug("BroadcastPorts returned null. Assuming single switch w/no links.");
			/* Must be a single-switch w/no links */
			broadcastPorts = Collections.singleton(OFPort.FLOOD);
		}
		
		for (OFPort p : broadcastPorts) {
			if (p.equals(inPort)) continue;
			actions.add(sw.getOFFactory().actions().output(p, Integer.MAX_VALUE));
		}
		pob.setActions(actions);
		// log.info("actions {}",actions);
		// set buffer-id, in-port and packet-data based on packet-in
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(inPort);
		pob.setData(pi.getData());

		try {
			if (logger.isTraceEnabled()) {
				logger.trace("Writing flood PacketOut switch={} packet-in={} packet-out={}",
						new Object[] {sw, pi, pob.build()});
			}
			messageDamper.write(sw, pob.build());
		} catch (IOException e) {
			logger.error("Failure writing PacketOut switch={} packet-in={} packet-out={}",
					new Object[] {sw, pi, pob.build()}, e);
		}
		
		// Create flow-mod based on packet-in and src-switch
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
		U64 cookie = AppCookie.makeCookie(APP_ID, 0);
		fmb.setCookie(cookie)
		.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
		.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setMatch(match)
		.setActions(actions);

		if (logger.isTraceEnabled()) {
			logger.trace("write flood flow-mod srcSwitch={} match={} " +
					"pi={} flow-mod={}",
					new Object[] {sw, match, pi, fmb.build()});
		}
		sw.write(fmb.build());
		return;		
	}
	
		// overloading doFlood to also accept actions as arguments
	 public void doFlood(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Match match, List<OFAction> actions) {
			OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
			// Set Action to flood
			OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
			Set<OFPort> broadcastPorts = topologyService.getSwitchBroadcastPorts(sw.getId());

			if (broadcastPorts == null) {
				logger.debug("BroadcastPorts returned null. Assuming single switch w/no links.");
				/* Must be a single-switch w/no links */
				broadcastPorts = Collections.singleton(OFPort.FLOOD);
			}
			
			for (OFPort p : broadcastPorts) {
				if (p.equals(inPort)) continue;
				actions.add(sw.getOFFactory().actions().output(p, Integer.MAX_VALUE));
			}
			pob.setActions(actions);
			// log.info("actions {}",actions);
			// set buffer-id, in-port and packet-data based on packet-in
			pob.setBufferId(OFBufferId.NO_BUFFER);
			pob.setInPort(inPort);
			pob.setData(pi.getData());

			try {
				if (logger.isTraceEnabled()) {
					logger.trace("Writing flood PacketOut switch={} packet-in={} packet-out={}",
							new Object[] {sw, pi, pob.build()});
				}
				messageDamper.write(sw, pob.build());
			} catch (IOException e) {
				logger.error("Failure writing PacketOut switch={} packet-in={} packet-out={}",
						new Object[] {sw, pi, pob.build()}, e);
			}
			
			// Create flow-mod based on packet-in and src-switch
//			OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
//			U64 cookie = AppCookie.makeCookie(APP_ID, 0);
//			fmb.setCookie(cookie)
//			.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
//			.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
//			.setBufferId(OFBufferId.NO_BUFFER)
//			.setMatch(match)
//			.setActions(actions);
//
//			if (logger.isTraceEnabled()) {
//				logger.trace("write flood flow-mod srcSwitch={} match={} " +
//						"pi={} flow-mod={}",
//						new Object[] {sw, match, pi, fmb.build()});
//			}
//			sw.write(fmb.build());
			return;		
		}
	
	 public void installAndSendout(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Match match, List<OFAction> actions) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		// List<OFAction> actions = new ArrayList<OFAction>();
		// Set<OFPort> broadcastPorts = this.topologyService.getSwitchBroadcastPorts(sw.getId());

//		if (broadcastPorts == null) {
//			logger.debug("BroadcastPorts returned null. Assuming single switch w/no links.");
//			/* Must be a single-switch w/no links */
//			broadcastPorts = Collections.singleton(OFPort.FLOOD);
//		}
//		
//		for (OFPort p : broadcastPorts) {
//			if (p.equals(inPort)) continue;
//			actions.add(sw.getOFFactory().actions().output(p, Integer.MAX_VALUE));
//		}
		pob.setActions(actions);
		// log.info("actions {}",actions);
		// set buffer-id, in-port and packet-data based on packet-in
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(inPort);
		pob.setData(pi.getData());

		try {
			if (logger.isTraceEnabled()) {
				logger.info("Writing installAndSendout PacketOut switch={} packet-in={} packet-out={}",
						new Object[] {sw, pi, pob.build()});
			}
			messageDamper.write(sw, pob.build());
		} catch (IOException e) {
			logger.info("Failure writing installAndSendout switch={} packet-in={} packet-out={}",
					new Object[] {sw, pi, pob.build()}, e);
		}
		
		// Create flow-mod based on packet-in and src-switch
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
		U64 cookie = AppCookie.makeCookie(APP_ID, 0);
		fmb 
		.setPriority(FLOWMOD_DEFAULT_PRIORITY)
		.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
		.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setMatch(match)
		.setActions(actions);

		if (logger.isTraceEnabled()) {
			logger.info("write installAndSendout flow-mod srcSwitch={} match={} " +
					"pi={} flow-mod={}",
					new Object[] {sw, match, pi, fmb.build()});
		}
		sw.write(fmb.build());
		return;		
	}
	
	/*overloading install and sendout to also accept ethernet frame for data
	 * 
	 */
	public void installAndSendout(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Match match, List<OFAction> actions, Ethernet eth) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setActions(actions);
		// log.info("actions {}",actions);
		// set buffer-id, in-port and packet-data based on packet-in
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(inPort);
		pob.setData(eth.serialize());

		try {
			if (logger.isTraceEnabled()) {
				logger.trace("Writing installAndSendout PacketOut switch={} packet-in={} packet-out={}",
						new Object[] {sw, pi, pob.build()});
			}
			messageDamper.write(sw, pob.build());
		} catch (IOException e) {
			logger.info("Failure writing installAndSendout switch={} packet-in={} packet-out={}",
					new Object[] {sw, pi, pob.build()}, e);
		}
		
		// Create flow-mod based on packet-in and src-switch
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
		U64 cookie = AppCookie.makeCookie(APP_ID, 0);
		fmb
		.setPriority(FLOWMOD_DEFAULT_PRIORITY)
		.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
		.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setMatch(match)
		.setActions(actions);

		if (logger.isTraceEnabled()) {
			logger.info("write installAndSendout flow-mod srcSwitch={} match={} " +
					"pi={} flow-mod={}",
					new Object[] {sw, match, pi, fmb.build()});
		}
		sw.write(fmb.build());
		return;		
	}
	
	/**
	 * Instead of using the Firewall's routing decision Match, which might be as general
	 * as "in_port" and inadvertently Match packets erroneously, construct a more
	 * specific Match based on the deserialized OFPacketIn's payload, which has been 
	 * placed in the FloodlightContext already by the Controller.
	 * 
	 * @param sw, the switch on which the packet was received
	 * @param inPort, the ingress switch port on which the packet was received
	 * @param cntx, the current context which contains the deserialized packet
	 * @return a composed Match object based on the provided information
	 */
	public Match createMatchFromPacket(IOFSwitch sw, OFPort inPort, FloodlightContext cntx) {
		// The packet in match will only contain the port number.
		// We need to add in specifics for the hosts we're routing between.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		VlanVid vlan = VlanVid.ofVlan(eth.getVlanID());
		MacAddress srcMac = eth.getSourceMACAddress();
		MacAddress dstMac = eth.getDestinationMACAddress();

		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.IN_PORT, inPort);

		if (FLOWMOD_DEFAULT_MATCH_MAC) {
			mb.setExact(MatchField.ETH_SRC, srcMac)
			.setExact(MatchField.ETH_DST, dstMac);
		}

		if (FLOWMOD_DEFAULT_MATCH_VLAN) {
			if (!vlan.equals(VlanVid.ZERO)) {
				mb.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(vlan));
			}
		}

		// TODO Detect switch type and match to create hardware-implemented flow
		if (eth.getEtherType() == EthType.IPv4) { /* shallow check for equality is okay for EthType */
			IPv4 ip = (IPv4) eth.getPayload();
			IPv4Address srcIp = ip.getSourceAddress();
			IPv4Address dstIp = ip.getDestinationAddress();
			
			if (FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
				mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				.setExact(MatchField.IPV4_SRC, srcIp)
				.setExact(MatchField.IPV4_DST, dstIp);
			}

			if (FLOWMOD_DEFAULT_MATCH_TRANSPORT) {
				/*
				 * Take care of the ethertype if not included earlier,
				 * since it's a prerequisite for transport ports.
				 */
				if (!FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
					mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				}
				
				if (ip.getProtocol().equals(IpProtocol.TCP)) {
					TCP tcp = (TCP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
					.setExact(MatchField.TCP_SRC, tcp.getSourcePort())
					.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
				} else if (ip.getProtocol().equals(IpProtocol.UDP)) {
					UDP udp = (UDP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
					.setExact(MatchField.UDP_SRC, udp.getSourcePort())
					.setExact(MatchField.UDP_DST, udp.getDestinationPort());
				}
			}
		} else if (eth.getEtherType() == EthType.ARP) { /* shallow check for equality is okay for EthType */
			mb.setExact(MatchField.ETH_TYPE, EthType.ARP);
		} else if (eth.getEtherType() == EthType.IPv6) {
			IPv6 ip = (IPv6) eth.getPayload();
			IPv6Address srcIp = ip.getSourceAddress();
			IPv6Address dstIp = ip.getDestinationAddress();
			
			if (FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
				mb.setExact(MatchField.ETH_TYPE, EthType.IPv6)
				.setExact(MatchField.IPV6_SRC, srcIp)
				.setExact(MatchField.IPV6_DST, dstIp);
			}

			if (FLOWMOD_DEFAULT_MATCH_TRANSPORT) {
				/*
				 * Take care of the ethertype if not included earlier,
				 * since it's a prerequisite for transport ports.
				 */
				if (!FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
					mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
				}
				
				if (ip.getNextHeader().equals(IpProtocol.TCP)) {
					TCP tcp = (TCP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
					.setExact(MatchField.TCP_SRC, tcp.getSourcePort())
					.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
				} else if (ip.getNextHeader().equals(IpProtocol.UDP)) {
					UDP udp = (UDP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
					.setExact(MatchField.UDP_SRC, udp.getSourcePort())
					.setExact(MatchField.UDP_DST, udp.getDestinationPort());
				}
			}
		}
		return mb.build();
	}
	
	public boolean isDhcpPacket(Ethernet frame) {
		IPacket payload = frame.getPayload(); // IP
		if (payload == null) return false;
		IPacket p2 = payload.getPayload(); // TCP or UDP
		if (p2 == null) return false;
		IPacket p3 = p2.getPayload(); // Application
		if ((p3 != null) && (p3 instanceof DHCP)) return true;
		return false;
	}
	
	public List<OFPort> find_tagToPort(VlanVid vid, int host_index, List<Map<OFPort, List<VlanVid> > > portToTag){
		List<OFPort> ports = new ArrayList<OFPort>();
		Map<OFPort, List<VlanVid> > dict = portToTag.get(host_index);	    
	    for(OFPort port : dict.keySet())
	    {
	    	List<VlanVid> tags = dict.get(port);
	    	if(tags.contains(vid))
	    		ports.add(port);
	    }
		return ports;
	}
	
	public void sendARPReply(IOFSwitch sw, OFPort inPort, OFPort outPort,
			MacAddress sourceMacAddress, MacAddress destinationMacAddress, byte priorityCode,
			MacAddress senderHardwareAddress, IPv4Address senderProtocolAddress,
			MacAddress targetHardwareAddress, IPv4Address targetProtocolAddress) {
		
		 // create a packet out message and set its fields
		IPacket arpReply = new Ethernet()
		.setSourceMACAddress(sourceMacAddress)
		.setDestinationMACAddress(destinationMacAddress)
		.setEtherType(EthType.ARP)
		.setPriorityCode(priorityCode)
		.setPayload(
				new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setHardwareAddressLength((byte) 6)
				.setProtocolAddressLength((byte) 4)
				.setOpCode(ARP.OP_REPLY)
				.setSenderHardwareAddress(senderHardwareAddress)
				.setSenderProtocolAddress(senderProtocolAddress)
				.setTargetHardwareAddress(targetHardwareAddress)
				.setTargetProtocolAddress(targetProtocolAddress)
				);
		
		
		
		// Initialize a packet out
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(inPort);
		
		// Set output actions
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(sw.getOFFactory().actions().output(outPort, Integer.MAX_VALUE));
		pob.setActions(actions);
		//po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
		
		// Set packet data and length
		byte[] packetData = arpReply.serialize();
		pob.setData(packetData);
		//pob.setLength((short) (OFPacketOut.MINIMUM_LENGTH + po.getActionsLength() + packetData.length));
		
		// Send packet
		try {
			//if (logger.isTraceEnabled()) {
				logger.info("Writing ARP reply PacketOut switch={}  packet-out={}",
						new Object[] {sw, pob.build()});
			//}
			messageDamper.write(sw, pob.build());
		} catch (IOException e) {
			logger.error("Failure writing installAndSendout switch={} packet-out={}",
					new Object[] {sw, pob.build()}, e);
		}
	}
	
	public void sendARPRequest(IOFSwitch sw, OFPort inPort, MacAddress sourceMacAddress,
			MacAddress senderHardwareAddress, IPv4Address senderProtocolAddress,
			IPv4Address targetProtocolAddress
			) {
		// packet out and set fields
		IPacket arpRequest = new Ethernet()
		.setSourceMACAddress(sourceMacAddress)
		.setDestinationMACAddress(MacAddress.of("ff:ff:ff:ff:ff:ff"))
		.setEtherType(EthType.ARP)
		.setPayload(
				new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setHardwareAddressLength((byte) 6)
				.setProtocolAddressLength((byte) 4)
				.setOpCode(ARP.OP_REQUEST)
				.setSenderHardwareAddress(senderHardwareAddress)  // an unassigned mac id that it generates a PACKET_IN
				.setSenderProtocolAddress(senderProtocolAddress)
				.setTargetHardwareAddress(MacAddress.of("00:00:00:00:00:00"))
				.setTargetProtocolAddress(targetProtocolAddress)
				);
		// Initialize a packet out
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(inPort);
		
		// Set output actions
		List<OFAction> actions = new ArrayList<OFAction>();
		Set<OFPort> broadcastPorts = topologyService.getSwitchBroadcastPorts(sw.getId());

		if (broadcastPorts == null) {
			logger.debug("BroadcastPorts returned null. Assuming single switch w/no links.");
			/* Must be a single-switch w/no links */
			broadcastPorts = Collections.singleton(OFPort.FLOOD);
		}
		
		for (OFPort p : broadcastPorts) {
			if (p.equals(inPort)) continue;
			actions.add(sw.getOFFactory().actions().output(p, Integer.MAX_VALUE));
		}
		pob.setActions(actions);
		//po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
		
		// Set packet data and length
		byte[] packetData = arpRequest.serialize();
		pob.setData(packetData);
		//pob.setLength((short) (OFPacketOut.MINIMUM_LENGTH + po.getActionsLength() + packetData.length));
		
		// Send packet
		try {
			//if (logger.isTraceEnabled()) {
				logger.info("Writing ARP reply PacketOut switch={}  packet-out={}",
						new Object[] {sw, pob.build()});
			//}
			messageDamper.write(sw, pob.build());
		} catch (IOException e) {
			logger.error("Failure writing installAndSendout switch={} packet-out={}",
					new Object[] {sw, pob.build()}, e);
		}
	}
	
	policyDecision getPolicy(ConcurrentHashMap<IPv4Address, ConcurrentHashMap<IPv4Address, Boolean> > interVmPolicy, IPv4Address src, IPv4Address dst)
	{
		logger.info("intervmpolicy {}", interVmPolicy);
		policyDecision ret = policyDecision.DEFAULT;
		if(interVmPolicy.get(src) == null && interVmPolicy.get(dst) == null) // the entry does not exists in the table
		{
			ret = policyDecision.DEFAULT;
		}
		else if (interVmPolicy.get(src) == null) //dst is there as first 
		{
			if(interVmPolicy.get(dst).get(src) == null) //dst is first but src is not second
				ret = policyDecision.DEFAULT;
			else //dst is first and src is second
				ret = interVmPolicy.get(dst).get(src) == true? policyDecision.ALLOW : policyDecision.DISALLOW;
		}
		else if (interVmPolicy.get(dst) == null) // src is there as first
		{
			if(interVmPolicy.get(src).get(dst) == null) //src is first but dst is not second
				ret = policyDecision.DEFAULT;
			else //src is first and dst is second
				ret = interVmPolicy.get(src).get(dst) == true? policyDecision.ALLOW : policyDecision.DISALLOW; 
		}
		
		else // none of them is null
		{
			if(interVmPolicy.get(src).get(dst) != null)
				ret = interVmPolicy.get(src).get(dst) == true? policyDecision.ALLOW : policyDecision.DISALLOW;
			else if (interVmPolicy.get(dst).get(src) != null)
				ret = interVmPolicy.get(dst).get(src) == true? policyDecision.ALLOW : policyDecision.DISALLOW;
			else//they both were at first position but the pair could not be made
				ret = policyDecision.DEFAULT;
		}
		
		logger.info("decision {}", ret);
		return ret;
	}

}
