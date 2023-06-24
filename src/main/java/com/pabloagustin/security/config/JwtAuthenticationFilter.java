package com.pabloagustin.security.config;

// -------------- AUTHENTICATION FILTER --------------

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.lang.NonNull;

import java.io.IOException;

// We want to keep this filter active every time the user make an HTTP request!
// Implement the methods from OncePerRequestFilter (httpservletrequest, response and chain)
// And we will work with this filter for our API to incoming http request.
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	// JWT SERVICE CLASS TO manage the information to validate the username by email!
	private final JwtService jwtService;

	// User detail service -> interface available from spring framework!
	private final UserDetailsService userDetailsService;


	@Override
	protected void doFilterInternal(
			// We can intercept every request and make extract data from the request and provide new data from the response
			@NonNull HttpServletRequest request,
			@NonNull HttpServletResponse response,
			// List of the other filter that we need to execute
			@NonNull FilterChain filterChain
	) throws ServletException, IOException {
		// Operations
		// When we make a call we need to pass JWT auth token within the header
		final String authHeader = request.getHeader("Authorization");
		// Jwt token and checking, let's implement this
		final String jwt;
		// THIS IS FOR JWT SERVICE USERNAME
		final String userEmail;
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			// Pass the request to the next filter! -> IMPORTANT!
			filterChain.doFilter(request, response);
			return;
		}
		// Let's extract the token from the auth header
		jwt = authHeader.substring(7);

		// After checking the jwt token we need to call a UserDetailService to check if the user exist in the database
		// To do this we need to call to the JWT SERVICE to get the username

		userEmail = jwtService.extractUsername(jwt); // to do extract the userEmail from JWT token; we need the class to manipulate this JWT TOKEN!
		// SecurityContextHolder.getContext().getAuthentication() == null -> It's for users that are not connecting yet!
		// (ESP) Si tenemos el usuario (userEmail) Y si ese usuario no esta conectado, haremos lo siguiente
		if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
			// Obtenemos los detalles del usuario de la Base de Datos
			UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
			// Luego, chequeamos si el usuario es VALIDO o no (usuario y token)
			if(jwtService.isTokenValid(jwt, userDetails)) {
				// Si es valido, creamos un objeto de tipo username y sus parametros
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
						userDetails,
						null,
						userDetails.getAuthorities()
				);
				authToken.setDetails(
						new WebAuthenticationDetailsSource()
								.buildDetails(request)
				);
				// Actualizamos el security context holder
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		// Always call it. We need to pass to the next filter to execute!
		filterChain.doFilter(request, response);
	}
}
