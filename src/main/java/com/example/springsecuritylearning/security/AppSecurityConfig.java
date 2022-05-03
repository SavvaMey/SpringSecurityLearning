package com.example.springsecuritylearning.security;

import com.example.springsecuritylearning.auth.ApplicationUserService;
import com.example.springsecuritylearning.jwt.JwtConfig;
import com.example.springsecuritylearning.jwt.JwtTokenVerifier;
import com.example.springsecuritylearning.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.example.springsecuritylearning.security.ApplicationUserRole.*;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public AppSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, JwtConfig jwtConfig, SecretKey secretKey) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }


//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails annaSmithUser = User.builder()
//                .username("anasmith")
//                .password(passwordEncoder.encode("password"))
//             //   .roles(STUDENT.name()) //ROLE_STUDENT
//                .authorities(STUDENT.getGrantedAuthorities())
//                .build();
//
//        UserDetails lindaUser = User.builder()
//                .username("linda")
//                .password(passwordEncoder.encode("password123"))
//       //         .roles(ADMIN.name())
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails tomeUser = User.builder()
//                .username("tom")
//                .password(passwordEncoder.encode("password123"))
//          //      .roles(ADMINTRAINEE.name())
//                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//        return new InMemoryUserDetailsManager(annaSmithUser, lindaUser, tomeUser);
 //   }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey),JwtUsernameAndPasswordAuthenticationFilter.class )
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "js/*").permitAll()
                .antMatchers("/api/**").hasAnyRole(STUDENT.name())
                .anyRequest()
                .authenticated();
//                .and()
//                .formLogin()
//                    .loginPage("/login")
//                    .permitAll()
//                    .defaultSuccessUrl("/courses", true)
//                    .passwordParameter("password")
//                    .usernameParameter("username")
//                .and()
//                .rememberMe()
//                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                    .key("somethingverysecured")  //defaults 2 weeks
//                    .rememberMeParameter("remember-me")
//                .and()
//                .logout()
//                    .logoutUrl("/logout")
//                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID", "remember-me")
//                    .logoutSuccessUrl("/login");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());

    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
