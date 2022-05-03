package com.example.springsecuritylearning.auth;

import com.google.common.collect.Lists;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.springsecuritylearning.security.ApplicationUserRole.*;

@Repository("fake")
public record FakeApplicationUserDaoService(
        PasswordEncoder passwordEncoder) implements ApplicationUserDao {

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        return Lists.newArrayList(
                new ApplicationUser(
                        STUDENT.getGrantedAuthorities(), passwordEncoder.encode("password"), "annasmith",
                        true, true, true, true
                ),
                new ApplicationUser(
                        ADMIN.getGrantedAuthorities(), passwordEncoder.encode("password"), "linda",
                        true, true, true, true
                ),
                new ApplicationUser(
                        ADMINTRAINEE.getGrantedAuthorities(), passwordEncoder.encode("password"), "tom",
                        true, true, true, true
                )
        );
    }
}
