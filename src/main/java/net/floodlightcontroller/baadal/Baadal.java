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
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
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
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.ForwardingBase;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.util.OFMessageDamper;

public class Baadal implements IFloodlightModule, IOFMessageListener, IBaadalService {
	protected IFloodlightProviderService floodlightProvider;
	private static final short APP_ID = 99;
	protected static Logger logger;
	TimerTask task;
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
	//Map<IPv4Address, MacAddress> ipToMac = new ConcurrentHashMap<IPv4Address, MacAddress> ();
	Map<IPv4Address, VlanVid> ipToTag;
	ConcurrentHashMap<IPv4Address, ConcurrentHashMap<IPv4Address, Boolean> > interVmPolicy;
	protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
	protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms
	
	protected baadalUtils bu;
	protected baadalHost bh1, bh2;
	protected baadalGeneral bg;
	
	protected IRestApiService restApi;

	
	
	protected Command processPacketIn(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
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
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IBaadalService.class);
	    return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
	    m.put(IBaadalService.class, this);
	    return m;				
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
		        new ArrayList<Class<? extends IFloodlightService>>();
		    l.add(IFloodlightProviderService.class);
		    l.add(ITopologyService.class);
		    l.add(IRestApiService.class);
		    return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
				EnumSet.of(OFType.FLOW_MOD),
				OFMESSAGE_DAMPER_TIMEOUT);
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		restApi = context.getServiceImpl(IRestApiService.class);
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
		

		
		//initialize ipToTag
		ipToTag = new ConcurrentHashMap<IPv4Address, VlanVid>();
//		ipToTag.put(IPv4Address.of("10.0.0.6"), VlanVid.ofVlan(0));
//		ipToTag.put(IPv4Address.of("10.0.0.7"), VlanVid.ofVlan(0));
//		ipToTag.put(IPv4Address.of("10.0.4.11"), VlanVid.ofVlan(4));
//		ipToTag.put(IPv4Address.of("10.0.2.25"), VlanVid.ofVlan(2));
//		ipToTag.put(IPv4Address.of("10.0.2.15"), VlanVid.ofVlan(2));
//		ipToTag.put(IPv4Address.of("10.0.2.28"), VlanVid.ofVlan(2));
//		ipToTag.put(IPv4Address.of("10.0.4.10"), VlanVid.ofVlan(4));
//		ipToTag.put(IPv4Address.of("10.0.4.25"), VlanVid.ofVlan(4));
//		ipToTag.put(IPv4Address.of("10.0.4.17"), VlanVid.ofVlan(4));
		
		//initialize inter vlan routing policy
		ConcurrentHashMap<IPv4Address, Boolean> submap = new ConcurrentHashMap<IPv4Address,Boolean>();
		interVmPolicy = new ConcurrentHashMap<IPv4Address, ConcurrentHashMap<IPv4Address, Boolean>>();
		submap.put(IPv4Address.of("10.0.2.28"), true);
		interVmPolicy.put(IPv4Address.of("10.0.4.17"), submap);

		ConcurrentHashMap<IPv4Address, ArrayList<IPv4Address>> x;
		// initialize baadalUtils;
		bu = new baadalUtils(topologyService, messageDamper, APP_ID, logger);
		
		// initialize baadalHosts
		bh1 = new baadalHost(logger, bu, dpid_hosts, macToTag, portToTag, IPv4Address.of("10.0.0.6"), ipToTag, interVmPolicy);
		bh2 = new baadalHost(logger, bu, dpid_hosts, macToTag, portToTag, IPv4Address.of("10.0.0.7"), ipToTag, interVmPolicy);
		
		//initialize central bridge
		bg = new baadalGeneral(logger, bu, dpid_hosts, macToTag, portToTag, IPv4Address.of("10.0.0.1"));
		
		/*
		 * Timer tasks for clearing data structures
		 * like iptotag
		 * */
		task = new TimerTask(){
			 @Override
		      public void run() {
		        // task to run goes here
		        System.out.println("Hello !!!");
		        ipToTag.clear();
		        logger.info("iptotag {}", ipToTag);
		      }
		    };
		Timer timer = new Timer();
		long delay = 0;
	    long intevalPeriod = 10 * 1000; 
		    
		    // schedules the task to be run in an interval 
		timer.scheduleAtFixedRate(task, delay,
		                                intevalPeriod);
		



		
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		restApi.addRestletRoutable(new baadalWebRoutable());

	}

	@Override 
	public void addIpToTag(ConcurrentHashMap<IPv4Address, VlanVid> _ipToTag) {
		// TODO Auto-generated method stub
		for(IPv4Address ipv4 : _ipToTag.keySet())
		{
			ipToTag.put(ipv4, _ipToTag.get(ipv4));
		}
		
		bh1.setIPToTag(ipToTag);
		bh1.setIPToTag(ipToTag);
	}

	@Override
	public Map<IPv4Address, VlanVid> getIpToTag() {
		//ipToTag.put(IPv4Address.of("99.99.99.99"), VlanVid.ofVlan(99));
		//ipToTag.clear();
		return ipToTag;
	}
	
	public boolean getInterVlanStatus(){
		return true;
	}

	@Override  
	public ConcurrentHashMap<IPv4Address, ConcurrentHashMap<IPv4Address, Boolean>> getInterVmPolicy() {
		// TODO Auto-generated method stub
		return interVmPolicy;
	}

	@Override
	public void addInterVmPolicy(List< List<Object> > policies) {
		// TODO Auto-generated method stub
		for(List<Object> policy : policies)
		{
			IPv4Address ip1 = (IPv4Address) policy.get(0);
			IPv4Address ip2 = (IPv4Address) policy.get(1);
			boolean decision = (boolean) policy.get(2);
			
			// add policy in intervmpolicy
			
			// if the entry does not exist, then create an  entry
			if(interVmPolicy.get(ip1) == null && interVmPolicy.get(ip2) == null)
			{
				ConcurrentHashMap<IPv4Address, Boolean> submap = new ConcurrentHashMap<IPv4Address,Boolean>();
				submap.put(ip2, decision);
				interVmPolicy.put(ip1, submap);
				continue;
			}
			else if (interVmPolicy.get(ip1) == null) // ip2 is there as first
			{
				 //ip2 is first but ip1 is not second				
					interVmPolicy.get(ip2).put(ip1, decision);	
					continue;
			}
			else if (interVmPolicy.get(ip2) == null) // ip1 is there as first
			{
				interVmPolicy.get(ip1).put(ip2, decision);
				continue;
			}
			else //none of them is null
			{
				if(interVmPolicy.get(ip1).get(ip2) != null)
					interVmPolicy.get(ip1).put(ip2, decision);
				else if (interVmPolicy.get(ip2).get(ip1) != null)
					interVmPolicy.get(ip2).put(ip1, decision);
				else // both were present as first entry but still a pair couldn't be made
					interVmPolicy.get(ip1).put(ip2,  decision);
				
				continue;
			}
		}
		logger.info("interVmPolicy {}", interVmPolicy);
	}

}
