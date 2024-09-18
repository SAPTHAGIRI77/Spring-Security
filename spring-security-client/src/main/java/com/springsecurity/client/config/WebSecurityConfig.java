package com.springsecurity.client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@Component
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(11);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                //.csrf().disable() // Disable CSRF if not using stateful authentication
                .authorizeRequests(authorizeRequests ->
                        {
                            try {
                                authorizeRequests
                                        .requestMatchers("/register").permitAll()
                                        .requestMatchers("/ping").permitAll()// Allow access to /registerapi
                                        .requestMatchers("/api/**").authenticated()
                                        .and()
                                        .oauth2Login(oauth2login ->
                                                oauth2login.loginPage("/oauth2/authorization/api-client-oidc"))
                                        .oauth2Client(Customizer.withDefaults());
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }

                        // Require authentication for other requests
                )
                .csrf(csrf -> csrf
                        .disable() // Disable CSRF if not using stateful authentication
                );// Configure default form login

        return http.build();
    }

}
