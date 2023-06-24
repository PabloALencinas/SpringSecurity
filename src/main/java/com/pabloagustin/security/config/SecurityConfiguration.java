package com.pabloagustin.security.config;

import com.pabloagustin.security.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

	// Instance an JwtAuthenticationFilter object to work with in our SecurityFilterChain
	private final JwtAuthenticationFilter jwtAuthFilter;

	private final AuthenticationProvider authenticationProvider;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
				.csrf()
				.disable() // Disable CSRF
				// What are the URL or PATHs that we want to secure (WhiteList pass below)
				// Creating an account for example. We do not need a jwt token
				// And log in -> We do not have to pass a token as a parameter because we do not have one yet!
				.authorizeHttpRequests()
				.requestMatchers("/api/v1/auth/**") // WHITELIST HERE! - This will represent our app patterns
				.permitAll()
				.anyRequest()
				// Each request needs to be authenticated
				.authenticated()
				.and()
				.sessionManagement()
				// A new session for each request
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				// Authentication provider
				.authenticationProvider(authenticationProvider)
				// I want to execute this filter before the filter call username password authentication filter
				.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);


		return http.build();
	}
}
