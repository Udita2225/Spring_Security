package Spring_Security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;



@Component
public class JwtUtils {
//    Format in which the token is sent as Header to the server:- key - value pair
//    Authorization : Bearer <token>

//    1. Getting the JWT (tokens) From Header
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    public String getJwtFromHeader(HttpServletRequest request){
    String bearerToken = request.getHeader("Authorization");
    logger.debug("Authorization Header: {}", bearerToken);
    if(bearerToken != null && bearerToken.startsWith("Bearer ")){
        return bearerToken.substring(7);
    }
    return null;
}

//    2. Generating Token From UserName
    public String  generateTokenFromUserName(UserDetails userDetails){
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

//    3. Getting Username from JWT Token
    public String getUserNameFromJWTToken(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }
//    4. Generate Signing Key
    public Key key(){
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(jwtSecret)
        );
    }

//    5. Validate JWT Token
    public boolean validateJwtToken(String authToken){
        try{
            System.out.println("Validate");

            Jwts.parser()
                    .verifyWith((SecretKey)key())
                    .build().parseSignedClaims(authToken);
            return true;
        }catch(MalformedJwtException exception){
            logger.error("Invalid JWT token: {}", exception.getMessage());
        }catch(ExpiredJwtException e){
            logger.error("JWT token is expired: {}", e.getMessage());
        }catch(UnsupportedJwtException e){
            logger.error("JWT token is unsupported: {}", e.getMessage());
        }catch(IllegalArgumentException e){
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

}
