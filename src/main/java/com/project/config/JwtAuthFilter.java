package com.project.config;

import java.io.IOException;

import org.aspectj.weaver.NewConstructorTypeMunger;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;


@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter{

	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;
	
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		final String prefix = "Bearer ";
		if(authHeader == null || !authHeader.startsWith(prefix)) {
			filterChain.doFilter(request, response);//brak nagłówka z tokenem, tylko przetwarzanie
			return;
		}
		
		final String token = authHeader.substring(prefix.length());
		final String userName = jwtService.extractUserName(token);//e-mail
		
		
		if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = this.userDetailsService.loadUserByUsername(userName);
			if(jwtService.isTokenValid(token, userDetails)) {
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		
		filterChain.doFilter(request, response);//o tym trzeba pamiętać, aby umożliwić przetwarzanie
		
	}

}











