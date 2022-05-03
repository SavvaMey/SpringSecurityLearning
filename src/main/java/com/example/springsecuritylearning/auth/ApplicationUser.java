package com.example.springsecuritylearning.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Set;

public record ApplicationUser(
        Set<? extends GrantedAuthority> grantedAuthorities,
        String password, String username, boolean isAccountNonExpired, boolean isAccountNonLocked,
        boolean isCredentialsNonExpired, boolean isEnabled) implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }
}
