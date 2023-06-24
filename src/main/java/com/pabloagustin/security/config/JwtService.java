package com.pabloagustin.security.config;

// -------------- JWT VALIDATE PROCESS --------------

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {


	private static final String SECRET_KEY = "2948404D635166546A576D5A7134743777217A25432A462D4A614E645267556B";

	// A simple Overview of "parts" inside a JWT token
	// We have the "HEADER": ALGORITHM & TOKEN TYPE
	// "PAYLOAD": DATA -> CLAIMS !IMPORTANT LOOK THE METHOD BELOW (extractUsername)
	// "VERIFY SIGNATURE"


	// Method to generate tokens!
	public String generateToken( Map<String, Object> extractClaims, UserDetails userDetails ){
		return Jwts
				.builder()
				.setClaims(extractClaims)
				.setSubject(userDetails.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // Valid for 24Hs + 1000 milliseconds
				.signWith(getSignIngKey(), SignatureAlgorithm.HS256)
				.compact();
	}

	// What if I want to generate a token without extractClaim ?
	// Generate token from userDetail itself!

	public String generateToken(UserDetails userDetails) {
		return generateToken(new HashMap<>(), userDetails);
	}

	// Method to VALIDATE A TOKEN!
	// Two parameters for -> is the current token matches with the user detail

	public boolean isTokenValid(String token, UserDetails userDetails){
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
	}

	private boolean isTokenExpired(String token) {
		// If is before the CURRENT DATE
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	public String extractUsername(String token) {
		// the Subject of the token, which will be the username/email
		return extractClaim(token, Claims::getSubject);
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	private Claims extractAllClaims(String token){
		return Jwts
				.parserBuilder()
				.setSigningKey(getSignIngKey())
				.build()
				.parseClaimsJws(token)
				.getBody();
	}

	private SecretKey getSignIngKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}

}
