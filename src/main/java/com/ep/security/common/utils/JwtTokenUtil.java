package com.ep.security.common.utils;

import com.ep.security.config.JwtAuthProperties;
import com.ep.security.dto.response.JwtResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.*;
import java.util.function.Function;

@Component
@RequiredArgsConstructor
public class JwtTokenUtil implements Serializable {

    private static final long serialVersionUID = -2550185165626007488L;
    public static final long ACCESS_TOKEN_VALIDITY = 5 * 60 * 60;
    public static final long REFRESH_TOKEN_VALIDITY = 7 * 60 * 60;
    public static final String AUTHORITIES = "authorities";
    public static final int EXPIRATION_ = 1000;

    private final AuthenticationManager authenticationManager;
    private final JwtAuthProperties jwtAuthProperties;

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(jwtAuthProperties.getSecretKey()).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public JwtResponse generateToken(UserDetails userDetails) {
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        JwtResponse jwtResponse = new JwtResponse();
        jwtResponse.setAccessToken(doGenerateToken(authorities, userDetails.getUsername()));
        return jwtResponse;
    }

    private String doGenerateToken(Collection<? extends GrantedAuthority> getAuthorities, String subject) {

        return Jwts.builder()
                .setSubject(subject)
                .claim(AUTHORITIES,
                        getAuthorities)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()
                        + ACCESS_TOKEN_VALIDITY * EXPIRATION_))
                .signWith(SignatureAlgorithm.HS512, jwtAuthProperties.getSecretKey())
                .compact();
    }


    public JwtResponse doGenerateRefreshToken(Map<String, Object> claims, String subject) {
        JwtResponse jwtResponse = new JwtResponse();
        jwtResponse.setAccessToken(Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()
                        + REFRESH_TOKEN_VALIDITY * EXPIRATION_))
                .signWith(SignatureAlgorithm.HS512, jwtAuthProperties.getSecretKey())
                .compact());
        return jwtResponse;

    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }


    public Map<String, Object> getMapFromJwtToken(Claims claims) {
        Map<String, Object> expectedMap = new HashMap<String, Object>();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            expectedMap.put(entry.getKey(), entry.getValue());
        }
        return expectedMap;
    }


    public void authenticate(String username, String password) throws Exception {
        Objects.requireNonNull(username);
        Objects.requireNonNull(password);

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }
}
