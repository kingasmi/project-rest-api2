package com.project.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.project.model.Role;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityWebConfig {
	private final JwtAuthFilter jwtAuthFilter;
	private final AuthenticationProvider authenticationProvider;
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
		http
			.csrf().disable() //disable Cross-Site Request Forgery
			.authorizeHttpRequests()
			.requestMatchers("/api/register", "/api/login").permitAll()
			.requestMatchers("/api/studenci/**").hasAuthority(Role.ADMIN.toString())
			.anyRequest().authenticated()
			.and()
			
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			
			.authenticationProvider(authenticationProvider)//Bean z security
			.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}
}
