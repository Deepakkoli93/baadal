package net.floodlightcontroller.baadal;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.VlanVid;
import org.restlet.data.Status;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.Put;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;



public class baadalPolicyResource extends ServerResource{
	protected static Logger logger = LoggerFactory.getLogger(baadalPolicyResource.class);
	
	/**
	 * Get basic info about the tool
	 * @return
	 */
	
	 @Get("json")
	 public Object handleRequest() {		
		 //return "{\"status\" : \"okay\", \"details\" : \"Invalid Operation\"}";
		 IBaadalService b =
	                (IBaadalService)getContext().getAttributes().
	                    get(IBaadalService.class.getCanonicalName());

	        return b.getInterVmPolicy();
	 }
	 
	 @Put
	 @Post
	 public Object addEntry(String json) throws IOException {		
		 List< List<Object> > policies = new ArrayList<List<Object>>();
		 IBaadalService b =
	                (IBaadalService)getContext().getAttributes().
	                    get(IBaadalService.class.getCanonicalName());
	        
		 MappingJsonFactory f = new MappingJsonFactory();
	        JsonParser jp;
	        
	        try {
	            jp = f.createParser(json);
	        } catch (JsonParseException e) {
	            throw new IOException(e);
	        }
	        
	        jp.nextToken(); 
	        
	        if(jp.getCurrentToken() != JsonToken.START_ARRAY){
	        	throw new IOException("Expected START_ARRAY");
	        }
	        while(jp.nextToken() != JsonToken.END_ARRAY){
		        if (jp.getCurrentToken() != JsonToken.START_OBJECT) {
		            throw new IOException("Expected START_OBJECT");
		        }
		        IPv4Address ip1, ip2;
		        boolean decision;
		        // get the first ip address
		            if (jp.nextToken() != JsonToken.FIELD_NAME) {
		                throw new IOException("Expected FIELD_NAME");
		            }
		            // check for name "ip"
		            if(!jp.getCurrentName().equals("ip"))
		            	throw new IOException("Expected ip");
		            else
		            {
		            	// get the value of ip
		            	jp.nextToken();
		            	// attempt to create ip address
		            	try{
		            		//logger.info("look here{} and {}", jp.getCurrentName(), jp.getText());
		            		ip1 = IPv4Address.of(jp.getText());
		            	}
		            	catch(Exception e)
		            	{
		            		logger.error("IP address 1 is not well formed " + e);
		            		return "IP address 1 is not well formed";
		            	}
		            }
		            
		           // get the second ip address
		            if (jp.nextToken() != JsonToken.FIELD_NAME) {
		                throw new IOException("Expected FIELD_NAME");
		            }
		            // check for name "ip"
		            if(!jp.getCurrentName().equals("ip"))
		            	throw new IOException("Expected ip");
		            else
		            {
		            	// get the value of ip
		            	jp.nextToken();
		            	// attempt to create ip address
		            	try{
		            		//logger.info("look here{} and {}", jp.getCurrentName(), jp.getText());
		            		ip2 = IPv4Address.of(jp.getText());
		            	}
		            	catch(Exception e)
		            	{
		            		logger.error("IP address 2 is not well formed " + e);
		            		return "IP address 2 is not well formed";
		            	}
		            }
		            // get the decision
		            if (jp.nextToken() != JsonToken.FIELD_NAME) {
		                throw new IOException("Expected FIELD_NAME");
		            }
		            // check for name "decision"
		            if(!jp.getCurrentName().equals("decision"))
		            	throw new IOException("Expected decision");
		            else
		            {
		            	// get the next token
		            	jp.nextToken();
		            	// attempt to create vlan tag
		            	try{
		            		decision = Boolean.valueOf(jp.getText());
		            	}
		            	catch(Exception e)
		            	{
		            		logger.error("Decision is not well formed, should be true or false" + e);
		            		return "Decision is not well formed, should be true or false";
		            	}
		            }
		            List<Object> policy = new ArrayList<Object>();
		            policy.add(ip1);policy.add(ip2);policy.add(decision);
		            policies.add(policy);
		            logger.info("policies {}",policies);
		            //jp.nextToken();
		            //logger.info("look here {} and {}", jp.getCurrentName(), jp.getText());
		       // }
		        
		        //jp.close();
		            if (jp.nextToken() != JsonToken.END_OBJECT) {
			            throw new IOException("Expected END_OBJECT");
			        }
	        }
	        jp.close();
	        b.addInterVmPolicy(policies);
	        setStatus(Status.SUCCESS_OK);
	        return "{\"status\":\"ok\"}";
	 }
	 
	
	

}
