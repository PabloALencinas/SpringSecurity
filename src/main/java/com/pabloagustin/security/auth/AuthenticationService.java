package com.pabloagustin.security.auth;

import com.pabloagustin.security.config.JwtService;
import com.pabloagustin.security.user.Role;
import com.pabloagustin.security.user.User;
import com.pabloagustin.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

	private final UserRepository repository;

	// This for password encoder
	private final PasswordEncoder passwordEncoder;

	// For JWT token generation
	private final JwtService jwtService;

	// For authenticate method
	private final AuthenticationManager authenticationManager;


	public AuthenticationResponse register(RegisterRequest request) {
		// Create a user, saved in DB and return the generated token
		var user = User.builder()
				.firstname(request.getFirstname())
				.lastname(request.getLastname())
				.email(request.getEmail())
				// Encoded the password!
				.password(passwordEncoder.encode(request.getPassword()))
				.role(Role.USER)
				.build();
		repository.save(user);
		// Return this auth response that contains the token
		var jwtToken = jwtService.generateToken(user);

		return AuthenticationResponse
				.builder()
				.token(jwtToken)
				.build();
	}

	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		// Secure authentication for user
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						request.getEmail(),
						request.getPassword()
				)
		);
		// If we get here means that the user is successfully authenticated
		var user = repository.findByEmail(request.getEmail())
				.orElseThrow();
		// Return this auth response that contains the token
		var jwtToken = jwtService.generateToken(user);

		return AuthenticationResponse
				.builder()
				.token(jwtToken)
				.build();
	}
}
