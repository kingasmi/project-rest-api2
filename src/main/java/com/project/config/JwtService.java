package com.project.config;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;


@Service
public class JwtService {

	private final SecretKey signKey;
	private final Integer tokenValidityInMiN;

	
	public JwtService(@Value("$(jwt.secret-key)") String secrectKey, 
						@Value("$(jwt.token-validity-in-min)") Integer tokenValidityInMin) {
		this.signKey = Keys.hmacShaKeyFor(secrectKey.getBytes(StandardCharsets.UTF_8));
		this.tokenValidityInMiN = tokenValidityInMin;
	}

	private SecretKey getSignKey() {
		return signKey;
	}
	
	public Claims extractAllClaims(String token) {
		return Jwts
				.parserBuilder()
				.setSigningKey(getSignKey())
				.build()
				.parseClaimsJws(token)
				.getBody();
	}
	
	public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
		final Claims claims = extractAllClaims(token);
		return claimResolver.apply(claims);
	}

	public String extractUserName(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}
	
	public boolean isTokenValid(String token, UserDetails userDetails) {
		final String userName = extractUserName(token);
		return userName.equals(userDetails.getUsername()) && !isTokenExpired(token);
	}

	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(Date.from(Instant.now()));
	}
	
	public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
		final Instant now = Instant.now();
		final Instant expiration = now.plus(tokenValidityInMiN, ChronoUnit.MINUTES);
		return Jwts
				.builder()
				.setClaims(extraClaims)
				.setSubject(userDetails.getUsername())
				.setIssuedAt(Date.from(now))
				.setExpiration(Date.from(expiration))
				.signWith(getSignKey(), SignatureAlgorithm.HS256)
				.compact();
	}
	
	public String generateToken(UserDetails userDetails) {
		return generateToken(Map.of(), userDetails);

	}
	
}












