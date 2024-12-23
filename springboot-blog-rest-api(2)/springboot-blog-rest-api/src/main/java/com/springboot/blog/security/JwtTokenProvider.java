package com.springboot.blog.security;

import com.springboot.blog.exception.BlogAPIException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;


@Configuration
public class JwtTokenProvider {



    @Value("@{app.jwt.secret}")
    private String jwtSecret;

    @Value("@{app-jwt-expiration-milliseconds}")
    private String jwtExpirationDate;

    //generate JWT token
    public String generateToken(Authentication authentication) {
        String username = authentication.getName();
        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime() + jwtExpirationDate);
        String token = Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(expireDate)
                .signWith(key())
                .compact();

        return token;
    }

                private Key key(){
           return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
        }

        //get username from jwt token
        public String getUsername(String token){
                    return Jwts.parser()
                            .verifyWith((SecretKey) key())   //verifying with key
                            .build()
                            .parseSignedClaims(token)
                            .getPayload()
                            .getSubject() ;     //basically returns username

        }
        //validate JWT token
        public boolean validateToken(){
                 try {
                     Jwts.parser()
                             .verifyWith((SecretKey) key())
                             .build()
                             .parse(token);

                     return true;
                 }
                 catch(MalFormedJwtException malformedJwtException){

                     throw new BlogAPIException(HttpStatus.BAD_REQUEST,"Expired jwt token");
                 }
                 catch(ExpiredJwtException expiredJwtException){

                     throw new BlogAPIException(HttpStatus.BAD_REQUEST,"Expired jwt token");

                 }
                 catch(UnspportedJwtException unsupportedJwtException){

                     throw new BlogAPIException(HttpStatus.BAD_REQUEST,"Expired jwt token");
                 }
                 catch(IllegalArguementException illegalArguementException ){
                     throw new BlogAPIException(HttpStatus.BAD_REQUEST,"JWt claims string is null or empty");
                 }
        }


    }
}
