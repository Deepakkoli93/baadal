package net.floodlightcontroller.baadal;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class baadalResource extends ServerResource{
	protected static Logger log = LoggerFactory.getLogger(baadalResource.class);
	
	/**
	 * Get basic info about the tool
	 * @return
	 */
	 @Get("json")
	 public Object handleRequest() {
//		 String op = (String) getRequestAttributes().get("op");
//	        IQoSService qos = 
//	                (IQoSService)getContext().getAttributes().
//	                get(IQoSService.class.getCanonicalName());
//	        
//	        if (op.equalsIgnoreCase("enable")) {
//	            qos.enableQoS(true);
//	            return "{\"status\" : \"success\", \"details\" : \"QoS Enabled\"}";
//	        }else if (op.equalsIgnoreCase("status")) {
//	            return qos.isEnabled();
//	        }else if (op.equalsIgnoreCase("disable")) {
//	        	qos.enableQoS(false);
//	         return "{\"status\" : \"success\", \"details\" : \"QoS Disabled\"}";
//	        }
//		 
		 return "{\"status\" : \"failure\", \"details\" : \"Invalid Operation\"}";
	 }
	

}
