package com.ep.security.controller;

import com.ep.security.common.constants.Constants;
import com.ep.security.common.utils.JwtTokenUtil;
import com.ep.security.dto.request.JwtRequest;
import com.ep.security.dto.response.JwtResponse;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class JwtAuthenticationController {

    private final JwtTokenUtil jwtTokenUtil;
    private final UserDetailsService jwtInMemoryUserDetailsService;

    @RequestMapping(value = "/generate-token", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) throws Exception {

        jwtTokenUtil.authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());
        final UserDetails userDetails = jwtInMemoryUserDetailsService
                .loadUserByUsername(authenticationRequest.getUsername());
        JwtResponse response = jwtTokenUtil.generateToken(userDetails);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @RequestMapping(value = "/refresh-token", method = RequestMethod.GET)
    public ResponseEntity<?> refreshToken(HttpServletRequest request) {

        Claims claims = jwtTokenUtil.getAllClaimsFromToken(request.getHeader(Constants.AUTHORIZATION));
        Map<String, Object> expectedMap = jwtTokenUtil.getMapFromJwtToken(claims);
        String token = jwtTokenUtil.doGenerateRefreshToken(expectedMap, expectedMap.get("sub").toString());
        return ResponseEntity.ok(token);
    }


    @GetMapping(value = "/users/me")
    public Principal me(Principal principal) {

        return principal;
    }

}
