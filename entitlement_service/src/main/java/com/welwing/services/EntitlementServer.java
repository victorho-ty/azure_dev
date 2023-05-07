package com.welwing.services;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;

import java.net.MalformedURLException;
import java.net.URL;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.Router;

/**
 * Java 17: https://simply-how.com/getting-started-with-java-17
 *          https://docs.oracle.com/en/java/javase/17/install/installation-jdk-macos.html#GUID-F9183C70-2E96-40F4-9104-F3814A5A331F
 * Azure JWT: https://zhuanlan.zhihu.com/p/423545781
 */
public class EntitlementServer
{
    public static void main(String[] args) {
        JwkProvider jwkProvider;
        try {
            jwkProvider = new UrlJwkProvider(new URL("https://login.microsoftonline.com/common/discovery/keys"));
        } catch (MalformedURLException ex) {
            ex.printStackTrace();
            return;
        }

        Vertx vertx = Vertx.vertx();
        HttpServer server = vertx.createHttpServer();
        Router router = Router.router(vertx);

        /**
         * @GET Method
         */
        Route getHandler = router.get("/checkToken").handler(routingContext -> {
            HttpServerRequest request = routingContext.request();
            // GET parameters
            String token = request.getParam("token");
            //String ip = request.getParam("ip");
            boolean is_valid = JwtValidator.validateToken(jwkProvider, token);
            routingContext.response().setChunked(true).end("" + is_valid);
        });

        int port = 9090;
        System.out.println("Server listening on port: " + port);
        server.requestHandler(router::handle).listen(port);
    }
}
