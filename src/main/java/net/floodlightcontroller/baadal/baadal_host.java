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

public class baadal_host implements IFloodlightModule, IOFMessageListener {
	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	private static final short APP_ID = 20;
	protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
	protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms

	public static int FLOWMOD_DEFAULT_IDLE_TIMEOUT = 5; // in seconds
	public static int FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	public static int FLOWMOD_DEFAULT_PRIORITY = 1; // 0 is the default table-miss flow in OF1.3+, so we need to use 1
	
	protected static boolean FLOWMOD_DEFAULT_SET_SEND_FLOW_REM_FLAG = false;
	
	protected static boolean FLOWMOD_DEFAULT_MATCH_VLAN = true;
	protected static boolean FLOWMOD_DEFAULT_MATCH_MAC = true;
	protected static boolean FLOWMOD_DEFAULT_MATCH_IP_ADDR = true;
	protected static boolean FLOWMOD_DEFAULT_MATCH_TRANSPORT = true;

	protected static final short FLOWMOD_DEFAULT_IDLE_TIMEOUT_CONSTANT = 5;
	protected static final short FLOWMOD_DEFAULT_HARD_TIMEOUT_CONSTANT = 0;
	
	protected static boolean FLOOD_ALL_ARP_PACKETS = false;
	
	protected short LOCAL = (short) 65534; //baadal-br-int
	protected short TRUNK = 1; //eth0
	// protected OFPort LOCAL = 1;
	// protected short TRUNK = 1;
	List<Map<OFPort, List<VlanVid> > > portToTag = new ArrayList< Map<OFPort, List<VlanVid> > >();
	Map<MacAddress, OFPort> macToPort = new HashMap<MacAddress, OFPort>();;
	Map<MacAddress, VlanVid> macToTag = new HashMap<MacAddress, VlanVid>(); //need to initialize it with central switch's mac with value 0
	MacAddress central_switch_mac = MacAddress.of("16:87:82:b3:a4:4d");
	MacAddress dpid_nat_br = MacAddress.of("52:52:00:01:15:03");
	MacAddress dpid_controller_br = MacAddress.of("52:52:00:01:15:02");
	List<MacAddress> dpid_hosts = new ArrayList<MacAddress>();
	Map<IPv4Address, MacAddress> ipToMac = new HashMap<IPv4Address, MacAddress> ();
	
	
	// taken from forwarding class
	protected ITopologyService topologyService; //to get a list of ports that can send broadcast packets
	protected OFMessageDamper messageDamper; // to write to switch
	static {
		AppCookie.registerApp(APP_ID, "VirtualNetworkFilter");
	}
	
	/**
	 * Writes a FlowMod to a switch that inserts a drop flow.
	 * @param sw The switch to write the FlowMod to.
	 * @param pi The corresponding OFPacketIn. Used to create the OFMatch structure.
	 * @param cntx The FloodlightContext that gets passed to the switch.
	 */
	protected void doDropFlow(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Match match) {
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
		.setIdleTimeout(ForwardingBase.FLOWMOD_DEFAULT_IDLE_TIMEOUT)
		.setHardTimeout(ForwardingBase.FLOWMOD_DEFAULT_HARD_TIMEOUT)
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
	
	protected void doFlood(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Match match) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		// Set Action to flood
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		List<OFAction> actions = new ArrayList<OFAction>();
		Set<OFPort> broadcastPorts = this.topologyService.getSwitchBroadcastPorts(sw.getId());

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
	

	/**
	 * Creates a OFPacketOut with the OFPacketIn data that is flooded on all ports unless
	 * writes a flood mod to flood packet at all ports
	 * the port is blocked, in which case the packet will be dropped.
	 * @param sw The switch that receives the OFPacketIn
	 * @param pi The OFPacketIn that came to the switch
	 * @param cntx The FloodlightContext associated with this OFPacketIn
	 */
	
	protected void installAndSendout(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Match match, List<OFAction> actions) {
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
				logger.trace("Writing installAndSendout PacketOut switch={} packet-in={} packet-out={}",
						new Object[] {sw, pi, pob.build()});
			}
			messageDamper.write(sw, pob.build());
		} catch (IOException e) {
			logger.error("Failure writing installAndSendout switch={} packet-in={} packet-out={}",
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
			logger.trace("write installAndSendout flow-mod srcSwitch={} match={} " +
					"pi={} flow-mod={}",
					new Object[] {sw, match, pi, fmb.build()});
		}
		sw.write(fmb.build());
		return;		
	}
	
	//overloading install and sendout to also accept ethernet frame for data
	protected void installAndSendout(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Match match, List<OFAction> actions, Ethernet eth) {
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
			logger.error("Failure writing installAndSendout switch={} packet-in={} packet-out={}",
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
			logger.trace("write installAndSendout flow-mod srcSwitch={} match={} " +
					"pi={} flow-mod={}",
					new Object[] {sw, match, pi, fmb.build()});
		}
		sw.write(fmb.build());
		return;		
	}
	// overloading doFlood to also accept actions as arguments
	protected void doFlood(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, Match match, List<OFAction> actions) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		// Set Action to flood
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		Set<OFPort> broadcastPorts = this.topologyService.getSwitchBroadcastPorts(sw.getId());

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
	protected Match createMatchFromPacket(IOFSwitch sw, OFPort inPort, FloodlightContext cntx) {
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
	
	
	protected boolean isDhcpPacket(Ethernet frame) {
		IPacket payload = frame.getPayload(); // IP
		if (payload == null) return false;
		IPacket p2 = payload.getPayload(); // TCP or UDP
		if (p2 == null) return false;
		IPacket p3 = p2.getPayload(); // Application
		if ((p3 != null) && (p3 instanceof DHCP)) return true;
		return false;
	}
	
	protected List<OFPort> find_tagToPort(VlanVid vid, int host_index){
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
	
	protected void sendARPReply(IPacket packet, IOFSwitch sw, OFPort inPort, OFPort outPort) {
		
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
		byte[] packetData = packet.serialize();
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
	
	protected void sendARPRequest(IPacket packet, IOFSwitch sw, OFPort inPort) {
		
		// Initialize a packet out
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(inPort);
		
		// Set output actions
		List<OFAction> actions = new ArrayList<OFAction>();
		Set<OFPort> broadcastPorts = this.topologyService.getSwitchBroadcastPorts(sw.getId());

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
		byte[] packetData = packet.serialize();
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
	
	
	protected Command processPacketIn(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if(!dpid_hosts.contains(MacAddress.of(sw.getId())))
			return Command.CONTINUE;
		if(MacAddress.of(sw.getId()).equals(MacAddress.of("52:52:00:01:15:07")))
			return Command.CONTINUE;
		Command ret = Command.STOP;
		//learn mac to port mapping
		OFPort input_port = (msg.getVersion().compareTo(OFVersion.OF_12) < 0 ? msg.getInPort() : msg.getMatch().get(MatchField.IN_PORT));
		
		macToPort.put(eth.getSourceMACAddress(), input_port);
		// logger.info("mac to port {}",macToPort.toString());
		Match match = createMatchFromPacket(sw, input_port ,cntx);
		// logger.info("original match of the packet {} {}", input_port.toString() ,match.toString());
		List<OFAction> actions = new ArrayList<OFAction>();
		VlanVid vlanId = VlanVid.ofVlan(eth.getVlanID()); 
		// change to initialization
		OFPort output_port = null; 
		VlanVid outVlanTag = null;
		int host_index = dpid_hosts.indexOf(MacAddress.of(sw.getId())); 
		// String srcNetwork = macToGuid.get(eth.getSourceMACAddress());
		// If the host is on an unknown network we deny it.
		// We make exceptions for ARP and DHCP.
		// We do not handle ARP packets
		
//		if (eth.isBroadcast() || eth.isMulticast() || /*isDefaultGateway(eth) || */isDhcpPacket(eth)) {
//			ret = Command.CONTINUE;
//		} 
		if (eth.getEtherType() == EthType.ARP)
		{

			Command ret1 = Command.CONTINUE;
			ARP arp = (ARP) eth.getPayload();
			MacAddress hostmac = MacAddress.of("52:52:00:01:15:06");
			IPv4Address gateway1 = IPv4Address.of("10.0.4.1");
			IPv4Address gateway2 = IPv4Address.of("10.0.2.1");
			logger.info("details->{} target address-> {}",arp.toString(), arp.getTargetProtocolAddress().toString());
			logger.info("ARP packet details -> {}",arp.toString());
			logger.info("generate reply");
			
			// generate ARP reply
			if(arp.getOpCode().equals(ARP.OP_REQUEST))
			{
				if(arp.getSenderProtocolAddress().equals(IPv4Address.of("10.0.4.25")) && arp.getTargetProtocolAddress().equals(IPv4Address.of("10.0.4.1")))
				{
					IPacket arpReply = new Ethernet()
					.setSourceMACAddress(hostmac)
					.setDestinationMACAddress(eth.getSourceMACAddress())
					.setEtherType(EthType.ARP)
					.setPriorityCode(eth.getPriorityCode())
					.setPayload(
							new ARP()
							.setHardwareType(ARP.HW_TYPE_ETHERNET)
							.setProtocolType(ARP.PROTO_TYPE_IP)
							.setHardwareAddressLength((byte) 6)
							.setProtocolAddressLength((byte) 4)
							.setOpCode(ARP.OP_REPLY)
							.setSenderHardwareAddress(hostmac)
							.setSenderProtocolAddress(gateway1)
							.setTargetHardwareAddress(arp.getSenderHardwareAddress())
							.setTargetProtocolAddress(arp.getSenderProtocolAddress())
							);
				sendARPReply(arpReply, sw, OFPort.ZERO, input_port);
					return Command.STOP;
				};
				if(arp.getSenderProtocolAddress().equals(IPv4Address.of("10.0.2.15")) && arp.getTargetProtocolAddress().equals(IPv4Address.of("10.0.2.1")))
				{
					IPacket arpReply = new Ethernet()
					.setSourceMACAddress(hostmac)
					.setDestinationMACAddress(eth.getSourceMACAddress())
					.setEtherType(EthType.ARP)
					.setPriorityCode(eth.getPriorityCode())
					.setPayload(
							new ARP()
							.setHardwareType(ARP.HW_TYPE_ETHERNET)
							.setProtocolType(ARP.PROTO_TYPE_IP)
							.setHardwareAddressLength((byte) 6)
							.setProtocolAddressLength((byte) 4)
							.setOpCode(ARP.OP_REPLY)
							.setSenderHardwareAddress(hostmac)
							.setSenderProtocolAddress(gateway2)
							.setTargetHardwareAddress(arp.getSenderHardwareAddress())
							.setTargetProtocolAddress(arp.getSenderProtocolAddress())
							);
				sendARPReply(arpReply, sw, OFPort.ZERO, input_port);
					return Command.STOP;
				};
//			if(arp.getTargetProtocolAddress().equals(vm3ip))
//			{
//			IPacket arpReply = new Ethernet()
//				.setSourceMACAddress(vm1mac)
//				.setDestinationMACAddress(eth.getSourceMACAddress())
//				.setEtherType(EthType.ARP)
//				.setPriorityCode(eth.getPriorityCode())
//				.setPayload(
//						new ARP()
//						.setHardwareType(ARP.HW_TYPE_ETHERNET)
//						.setProtocolType(ARP.PROTO_TYPE_IP)
//						.setHardwareAddressLength((byte) 6)
//						.setProtocolAddressLength((byte) 4)
//						.setOpCode(ARP.OP_REPLY)
//						.setSenderHardwareAddress(vm3mac)
//						.setSenderProtocolAddress(vm3ip)
//						.setTargetHardwareAddress(arp.getSenderHardwareAddress())
//						.setTargetProtocolAddress(arp.getSenderProtocolAddress())
//						);
//			sendARPReply(arpReply, sw, OFPort.ZERO, input_port);
//			}
//			else if(arp.getTargetProtocolAddress().equals(vm4ip))
//			{
//				IPacket arpReply = new Ethernet()
//				.setSourceMACAddress(vm2mac)
//				.setDestinationMACAddress(eth.getSourceMACAddress())
//				.setEtherType(EthType.ARP)
//				.setPriorityCode(eth.getPriorityCode())
//				.setPayload(
//						new ARP()
//						.setHardwareType(ARP.HW_TYPE_ETHERNET)
//						.setProtocolType(ARP.PROTO_TYPE_IP)
//						.setHardwareAddressLength((byte) 6)
//						.setProtocolAddressLength((byte) 4)
//						.setOpCode(ARP.OP_REPLY)
//						.setSenderHardwareAddress(vm4mac)
//						.setSenderProtocolAddress(vm4ip)
//						.setTargetHardwareAddress(arp.getSenderHardwareAddress())
//						.setTargetProtocolAddress(arp.getSenderProtocolAddress())
//						);
//			sendARPReply(arpReply, sw, OFPort.ZERO, input_port);
//			}
			}
			// if it is a reply and target mac addr is that of host then save the port
			
			else if (arp.getOpCode().equals(ARP.OP_REPLY))
			{
				logger.info("arp replies : {}", arp);
				ipToMac.put(arp.getSenderProtocolAddress(), arp.getSenderHardwareAddress());

			}
			return ret1;
			
		}

		else if (eth.getEtherType() == EthType.IPv6)
		{
			doDropFlow(sw, msg, cntx, match);
			ret = Command.STOP;
		}
		
		else if (input_port == OFPort.of(LOCAL)) {
//			logger.info("coming from local port");
//			logger.info("Datapath id of switch {}", sw.getId().toString());
//			Match m = createMatchFromPacket(sw, input_port, cntx);
//			logger.info("Packet details {}",m.toString());
			macToTag.put(eth.getSourceMACAddress(),vlanId);
			if(eth.isBroadcast() || eth.isMulticast())
			{
				doFlood(sw, msg, cntx, match);
				ret = Command.STOP; // maybe drop this packet?
			}
			
			else
			{				
				if(macToPort.get(eth.getDestinationMACAddress()) != null)
				{
					output_port = macToPort.get(eth.getDestinationMACAddress());
					if(output_port == OFPort.of(TRUNK))
					{
						// if the tag is known
						if(macToTag.get(eth.getDestinationMACAddress()) != null)
						{
							outVlanTag = macToTag.get(eth.getDestinationMACAddress());
							
							if(outVlanTag.getVlan() == 0)
							{
								// not sure why Integer.MAX_VALUE
								
								actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
								installAndSendout(sw, msg, cntx, match, actions);
								// logger.info("Adding flow, packet is tagged with zero {} {}", match.toString(), actions.toString());
								ret = Command.STOP;
							}
							
							else
							{
								
								actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
								//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag));
								OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
								actions.add(sw.getOFFactory().actions().setField(vlan));
								actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
								installAndSendout(sw, msg, cntx, match, actions);
								ret = Command.STOP;
							}
						}
						
						// else if the tag is known
						else
						{
							logger.info("The tag is NOT known");
							actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
							installAndSendout(sw, msg, cntx, match, actions);
							ret = Command.STOP;
						}
					}
					
					// else if the port is LOCAL
					else
					{
						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
						installAndSendout(sw, msg, cntx, match, actions);
						ret = Command.STOP;
					}
				}
				
				// else if the outport is not known
				else
				{
					// output_port = OFPort.FLOOD;
					// actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
					// installAndSendout(sw, msg, cntx, match, actions);
					logger.info("output port not known, flooding!");
					doFlood(sw, msg, cntx, match, actions);
					ret = Command.STOP;
				}
					
			}
		} 
		
		// else if in port is TRUNK
		else if (input_port == OFPort.of(TRUNK))
		{
			//logger.info("coming from trunk port, Datapath id of switch {}", sw.getId().toString());
			Match m = createMatchFromPacket(sw, input_port, cntx);
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
					doFlood(sw, msg, cntx, match, actions);
					ret = Command.STOP;
				}
				else // tagged
				{
					// strip the vlan tag to send out of access ports in vlan
					actions.add(sw.getOFFactory().actions().popVlan());
//					output_port = OFPort.FLOOD;
//					actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
//					installAndSendout(sw, msg, cntx, match, actions);
					doFlood(sw, msg, cntx, match, actions);
					ret = Command.STOP;
				}
			}
			
			// else if packet is multicast
			else if (eth.isMulticast())
			{
				match = createMatchFromPacket(sw, input_port, cntx);
				
				if(vlanId.getVlan() == 0) // is untagged
				{
					doFlood(sw, msg, cntx, match, actions);
					ret = Command.STOP;
				}
				else // is tagged
				{
					actions.add(sw.getOFFactory().actions().popVlan());
					doFlood(sw, msg, cntx, match, actions);
					ret = Command.STOP;
				}
			}
			
			// if packet is unicast
			else
			{
				// my_match.dl_src = packet.src
				if(macToPort.get(eth.getDestinationMACAddress()) != null)
				{
					output_port = macToPort.get(eth.getDestinationMACAddress());
					if(vlanId.getVlan() == 0) // if untagged
					{
						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
						installAndSendout(sw, msg, cntx, match, actions);
						//logger.info("At trunk, Adding flow, packet is tagged with zero {} {}", match.toString(), actions.toString());
						ret = Command.STOP;
					}
					else // tagged
					{
						// strip the vlan tag
						actions.add(sw.getOFFactory().actions().popVlan());
						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
						installAndSendout(sw, msg, cntx, match, actions);
						ret = Command.STOP;
					}
				}
				else //output port unknown
				{
					if(vlanId.getVlan() == 0) // if tagged
					{
						//flood and install flow
						doFlood(sw, msg, cntx, match, actions);
						ret = Command.STOP;
					}
					else // untagged
					{
						// find ports in vlan "out_vlan_tag"
						List<OFPort> ports = find_tagToPort(vlanId, host_index);
						ports.remove(OFPort.of(TRUNK));
						
						// strip the vlan tag
						actions.add(sw.getOFFactory().actions().popVlan());
						
						// adding access ports in the vlan to out port list
						for(OFPort port : ports)
							actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
						
						actions.add(sw.getOFFactory().actions().output(OFPort.of(LOCAL), Integer.MAX_VALUE));
						installAndSendout(sw, msg, cntx, match, actions);
						ret = Command.STOP;
					}
				}
			}
		}
		else //inport is an access port
		{
			// macToTag global dict; learnt only when packets ingress from ACCESS port
			logger.info("host_index="+host_index+"input_port"+input_port+"src mac addr"+eth.getSourceMACAddress());			
			macToTag.put(eth.getSourceMACAddress(), portToTag.get(host_index).get(input_port).get(0));
			outVlanTag = portToTag.get(host_index).get(input_port).get(0);
			
			// if broadcast
			if(eth.isBroadcast())
			{
				// find the host
				host_index = dpid_hosts.indexOf(MacAddress.of(sw.getId()));
				
				// find ports in the vlan "out_vlan_tag"
				List<OFPort> ports = find_tagToPort(outVlanTag, host_index);
				
				actions.add(sw.getOFFactory().actions().output(OFPort.of(LOCAL), Integer.MAX_VALUE));
				// adding access ports in the vlan to out port list
				for(OFPort port : ports)
					actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
				
				// push vlan tag
				actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
				//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag));
				OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
				actions.add(sw.getOFFactory().actions().setField(vlan));
				
				// add trunk port in output too
				actions.add(sw.getOFFactory().actions().output(OFPort.of(TRUNK), Integer.MAX_VALUE));
				
				installAndSendout(sw, msg, cntx, match, actions);
				ret = Command.STOP;
			}
			
			// else if multicast
			else if(eth.isMulticast())
			{
				match = createMatchFromPacket(sw, input_port, cntx);
				
				// find the host
				host_index = dpid_hosts.indexOf(MacAddress.of(sw.getId()));
				
				// find ports in the vlan "out_vlan_tag"
				List<OFPort> ports = find_tagToPort(outVlanTag, host_index);
				
				actions.add(sw.getOFFactory().actions().output(OFPort.of(LOCAL), Integer.MAX_VALUE));
				// adding access ports in the vlan to out port list
				for(OFPort port : ports)
					actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
				
				// push vlan tag
				actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
				//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag));
				OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
				actions.add(sw.getOFFactory().actions().setField(vlan));
				
				// add trunk port in output too
				actions.add(sw.getOFFactory().actions().output(OFPort.of(TRUNK), Integer.MAX_VALUE));
				
				installAndSendout(sw, msg, cntx, match, actions);
				ret = Command.STOP;
			}
			
			else //unicast
			{
				IPv4 ipv4 = (IPv4) eth.getPayload();
				
				// if dest mac address is of host
				// and dest ip address if not of host then act as router and change destination mac addresses
				if(!ipv4.getDestinationAddress().equals(IPv4Address.of("10.0.0.6")) && eth.getDestinationMACAddress().equals(MacAddress.of("52:52:00:01:15:06")))
				{
//					if(ipv4.getSourceAddress().equals(IPv4Address.of("10.0.4.25")) && ipv4.getDestinationAddress().equals(IPv4Address.of("10.0.2.15")))
//					{
//						// do this from ip to mac table
//						eth.setDestinationMACAddress(MacAddress.of("a2:00:00:e8:30:77"));
//					    eth.setSourceMACAddress(MacAddress.of("52:52:00:01:15:06"));	
//					}
//					else if(ipv4.getSourceAddress().equals(IPv4Address.of("10.0.2.15")) && ipv4.getDestinationAddress().equals(IPv4Address.of("10.0.4.25")))
//					{
//						eth.setDestinationMACAddress(MacAddress.of("a2:00:00:79:3d:56"));
//					    eth.setSourceMACAddress(MacAddress.of("52:52:00:01:15:06"));	
//					}
					logger.info("iptomac : {}", ipToMac);
					// mac address is not known then send ARP request
					if(ipToMac.get(ipv4.getDestinationAddress()) == null)
					{
						IPacket arpRequest = new Ethernet()
						.setSourceMACAddress(MacAddress.of("52:52:00:01:15:06"))
						.setDestinationMACAddress(MacAddress.of("ff:ff:ff:ff:ff:ff"))
						.setEtherType(EthType.ARP)
						.setPayload(
								new ARP()
								.setHardwareType(ARP.HW_TYPE_ETHERNET)
								.setProtocolType(ARP.PROTO_TYPE_IP)
								.setHardwareAddressLength((byte) 6)
								.setProtocolAddressLength((byte) 4)
								.setOpCode(ARP.OP_REQUEST)
								.setSenderHardwareAddress(MacAddress.of("52:52:00:01:15:99"))  // an unassigned mac id that it generates a PACKET_IN
								.setSenderProtocolAddress(IPv4Address.of("10.0.0.6"))
								.setTargetHardwareAddress(MacAddress.of("00:00:00:00:00:00"))
								.setTargetProtocolAddress(ipv4.getDestinationAddress())
								);
						sendARPRequest(arpRequest, sw, OFPort.ZERO);
	
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
					    eth.setSourceMACAddress(MacAddress.of("52:52:00:01:15:06"));
					}
					
					// if output port is not known 
					if(macToPort.get(eth.getDestinationMACAddress()) == null)
					{
						IPacket arpRequest = new Ethernet()
						.setSourceMACAddress(MacAddress.of("52:52:00:01:15:06"))
						.setDestinationMACAddress(MacAddress.of("ff:ff:ff:ff:ff:ff"))
						.setEtherType(EthType.ARP)
						.setPayload(
								new ARP()
								.setHardwareType(ARP.HW_TYPE_ETHERNET)
								.setProtocolType(ARP.PROTO_TYPE_IP)
								.setHardwareAddressLength((byte) 6)
								.setProtocolAddressLength((byte) 4)
								.setOpCode(ARP.OP_REQUEST)
								.setSenderHardwareAddress(MacAddress.of("52:52:00:01:15:99"))  // an unassigned mac id that it generates a PACKET_IN
								.setSenderProtocolAddress(IPv4Address.of("10.0.0.6"))
								.setTargetHardwareAddress(MacAddress.of("00:00:00:00:00:00"))
								.setTargetProtocolAddress(ipv4.getDestinationAddress())
								);
						sendARPRequest(arpRequest, sw, OFPort.ZERO);
	
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
				

				
				logger.info("look here dest {}, src {}", ipv4.getDestinationAddress(), ipv4.getSourceAddress());
				logger.info("look here whole packet eth {} and ipv4 {}", eth.toString(), ipv4.toString());
				logger.info("mactoport {}", macToPort.toString());
				
				if(macToPort.get(eth.getDestinationMACAddress()) != null)
				{
					logger.info("Packet coming from access port, outport is known and is {} for mac address {}", 
					macToPort.get(eth.getDestinationMACAddress()), eth.getDestinationMACAddress());
					logger.info("mac to port -> {}",macToPort.toString());
					output_port = macToPort.get(eth.getDestinationMACAddress());
					
					if(output_port.getPortNumber() == TRUNK)
					{
						// push vlan tag
						actions.add(sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME));
						//actions.add(sw.getOFFactory().actions().setVlanVid(outVlanTag));
						OFOxmVlanVid vlan = sw.getOFFactory().oxms().vlanVid(OFVlanVidMatch.ofVlanVid(outVlanTag));
						actions.add(sw.getOFFactory().actions().setField(vlan));
						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
						installAndSendout(sw, msg, cntx, match, actions, eth);
						ret = Command.STOP;
					}
					else
					{
						actions.add(sw.getOFFactory().actions().output(output_port, Integer.MAX_VALUE));
						installAndSendout(sw, msg, cntx, match, actions, eth);
						ret = Command.STOP;
					}
				}
				
				else //output port is unknown
				{
					logger.info("Packet coming from access port, outport is NOT known");
					// find the host
					host_index = dpid_hosts.indexOf(MacAddress.of(sw.getId()));
					
					// find ports in the vlan "out_vlan_tag"
					List<OFPort> ports = find_tagToPort(outVlanTag, host_index);
					actions.add(sw.getOFFactory().actions().output(OFPort.of(LOCAL), Integer.MAX_VALUE));
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
					
					installAndSendout(sw, msg, cntx, match, actions);
					ret = Command.STOP;
				}
			}
			
		}
//		
		if (logger.isTraceEnabled())
			logger.trace("Results for flow between {} and {} is {}",
					new Object[] {eth.getSourceMACAddress(), eth.getDestinationMACAddress(), ret});
		/*
		 * TODO - figure out how to still detect gateways while using
		 * drop mods
        if (ret == Command.STOP) {
            if (!(eth.getPayload() instanceof ARP))
                doDropFlow(sw, msg, cntx);
        }
		 */
		return ret;
	}
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return baadal_host.class.getSimpleName();
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
		logger = (Logger) LoggerFactory.getLogger(baadal_host.class);
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
				portToTag1.put(OFPort.of(LOCAL), tags);
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
		
		
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		

	}

}
