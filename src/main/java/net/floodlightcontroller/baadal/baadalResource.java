package net.floodlightcontroller.baadal;

import java.io.IOException;

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



public class baadalResource extends ServerResource{
	protected static Logger logger = LoggerFactory.getLogger(baadalResource.class);
	
	/**
	 * Get basic info about the tool
	 * @return
	 */
	private int x = 1;
	
	 @Get("json")
	 public Object handleRequest() {		
		 //return "{\"status\" : \"okay\", \"details\" : \"Invalid Operation\"}";
		 IBaadalService b =
	                (IBaadalService)getContext().getAttributes().
	                    get(IBaadalService.class.getCanonicalName());
	        logger.info("x here is = "+x);
	        x = 100;
	        logger.info("x now is = "+x);
	        return b.getIpToTag();
	 }
	 
	 @Put
	 @Post
	 public Object addEntry(String json) throws IOException {		
		 //return "{\"status\" : \"okay\", \"details\" : \"Invalid Operation\"}";
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
	        
	        while (jp.nextToken() != JsonToken.END_OBJECT) {
	            if (jp.getCurrentToken() != JsonToken.FIELD_NAME) {
	                throw new IOException("Expected FIELD_NAME");
	            }
	            
	            jp.nextToken();
	            logger.info("look here {} and {}", jp.getCurrentName(), jp.getText());
	        }
	        
	        jp.close();
	        }
	        return json;
	 }
	 
	
	

}
