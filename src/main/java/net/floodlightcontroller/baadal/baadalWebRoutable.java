package net.floodlightcontroller.baadal;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;

public class baadalWebRoutable implements RestletRoutable{

	@Override
	public Restlet getRestlet(Context context) {
        Router router = new Router(context);
         router.attach("/ip2tag/json", baadalResource.class);
         router.attach("/intervlanstatus/json", baadalResource.class);
        return router;
	}

	@Override
	public String basePath() {
		// TODO Auto-generated method stub
        return "/wm/baadal";	}

}
