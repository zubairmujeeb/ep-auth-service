package com.ep.security.service;

import com.ep.security.common.constants.Constants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static com.ep.security.enums.ApplicationUserRole.ADMIN;
import static com.ep.security.enums.ApplicationUserRole.INTERN;


@Service
public class JwtUserDetailsService implements UserDetailsService {

    private final static String ADMIN_USER_NAME = "TelenorAdmin";
    private final static String ADMIN_USER_PASSWORD = "password";
    private final static String INTERN_USER_NAME = "TelenorIntern";
    private final static String INTERN_USER_PASSWORD = "password123";

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (ADMIN_USER_NAME.equalsIgnoreCase(username)) {
            return new User(ADMIN_USER_NAME,
                    passwordEncoder.encode(ADMIN_USER_PASSWORD),
                    ADMIN.getGrantedAuthorities());
        }
        if (INTERN_USER_NAME.equalsIgnoreCase(username)) {
            return new User(INTERN_USER_NAME,
                    passwordEncoder.encode(INTERN_USER_PASSWORD),
                    INTERN.getGrantedAuthorities());
        } else {
            throw new UsernameNotFoundException(Constants.USER_NOT_FOUND + username);
        }
    }

}