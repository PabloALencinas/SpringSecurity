package com.pabloagustin.security.config;

// ----------- APP CONFIG (such as Beans.. etc) -----------

import com.pabloagustin.security.user.UserRepository;
import jakarta.security.auth.message.config.AuthConfigProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

	// User Repository
	private final UserRepository repository;
	@Bean
	public UserDetailsService userDetailsService() {
		// Fetch with the DATABASE
		// Lambda Expression!
		return username -> repository.findByEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException("User not found!"));
	}

	@Bean
	public AuthenticationProvider authenticationProvider(){
		// Data access object which is responsible for fetch the user detail
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		// Properties
		authProvider.setUserDetailsService(userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		// Hold the information of authentication manager
		return config.getAuthenticationManager();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
