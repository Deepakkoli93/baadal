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
		 return "{\"status\" : \"failure\", \"details\" : \"Invalid Operation\"}";
	 }
	

}
