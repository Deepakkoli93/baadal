package net.floodlightcontroller.baadal;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;

public class baadalWebRoutable implements RestletRoutable{

	@Override
	public Restlet getRestlet(Context context) {
        Router router = new Router(context);
         router.attach("/list/json", baadalResource.class);
         router.attach("/json", baadalResource.class);
         router.attach("/policy/json", baadalPolicyResource.class);
        return router;
	}

	@Override
	public String basePath() {
		// TODO Auto-generated method stub
        return "/wm/baadal";	}

}
