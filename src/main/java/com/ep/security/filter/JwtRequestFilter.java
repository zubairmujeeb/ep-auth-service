package com.ep.security.filter;

import com.ep.security.common.utils.JwtTokenUtil;
import com.ep.security.service.JwtUserDetailsService;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.ep.security.common.constants.Constants.*;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {


    String username = null;
    String jwtToken = null;

    @Autowired
    JwtUserDetailsService jwtUserDetailsService;
    @Autowired
    JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        final String requestTokenHeader = request.getHeader(AUTHORIZATION);
        if (requestTokenHeader != null &&
                requestTokenHeader.startsWith(BEARER_)) {
            jwtToken = requestTokenHeader.substring(7);
            try {
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(JWT_TOKEN_NOT_FOUND);
            } catch (ExpiredJwtException e) {
                throw new IllegalArgumentException(JWT_TOKEN_EXPIRED);
            }
        }
        if (username != null &&
                SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);
            if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {

                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource()
                                .buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        chain.doFilter(request, response);
    }

}
