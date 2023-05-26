package com.project.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.project.config.JwtService;
import com.project.model.CustumUserDetails;
import com.project.model.Role;
import com.project.model.Student;
import com.project.service.StudentService;

import io.micrometer.common.lang.NonNull;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
	private final StudentService studentService;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;
	
		
	public void register(Student student) {
		student.setPassword(passwordEncoder.encode(student.getPassword()));
		student.setRole(Role.USER);
		studentService.setStudent(student);
	}
	
	
	public AuthResponse authenticate(@NonNull String email, @NonNull String password) {
		authenticationManager
			.authenticate(new UsernamePasswordAuthenticationToken(email, password));
		var user = studentService
				.searchByEmail(email)
				.map(s -> new CustumUserDetails(s))
				.orElseThrow(()-> new UsernameNotFoundException(String.format("User '%s' not found!", email)));
		var token = jwtService.generateToken(user);
		return AuthResponse.builder()
				.token(token)
				.build();
		
	}
	
	public AuthResponse authenticate(AuthRequest request) {
		return authenticate(request.getEmail(), request.getPassword());
		
	}
	
	public StudentService getStudentService() {
		return studentService;
	}
	public PasswordEncoder getPasswordEncoder() {
		return passwordEncoder;
	}
	public JwtService getJwtService() {
		return jwtService;
	}
	public AuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}
	
	

}
