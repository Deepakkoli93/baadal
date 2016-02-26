package net.floodlightcontroller.baadal;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;

public class baadalWebRoutable implements RestletRoutable{

	@Override
	public Restlet getRestlet(Context context) {
		// TODO Auto-generated method stub
        Router router = new Router(context);
        //router.attach("/tool/{op}/json", baadalResource.class);
         router.attach("/service/json", baadalResource.class);
        // router.attach("/policy/json", QoSPoliciesResource.class);
        return router;
	}

	@Override
	public String basePath() {
		// TODO Auto-generated method stub
        return "/wm/baadal";	}

}