package com.welwing.services;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Map;

public class JwtValidator {

    public static boolean validateToken(JwkProvider jwkProvider, String token) {
        DecodedJWT jwt = JWT.decode(token);
        System.out.println("Token kid: " + jwt.getKeyId());

        Jwk jwk;
        Algorithm algorithm;
        try {
            jwk = jwkProvider.get(jwt.getKeyId());
            algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            algorithm.verify(jwt);// if the token signature is invalid, the method will throw SignatureVerificationException

            Date expiry = jwt.getExpiresAt();
            System.out.println("Expiry: " + expiry);
            if (expiry.after(new Date())) {
                System.out.println("=== Token Valid ===");
                Map<String, Claim> claims = jwt.getClaims();
                System.out.println(claims);
                return true;
            } else {
                System.out.println("Token Expired");
            }
        } catch (JwkException e) {
            e.printStackTrace();
        } catch(SignatureVerificationException e){
            e.printStackTrace();
        }
        return false;
    }
}
