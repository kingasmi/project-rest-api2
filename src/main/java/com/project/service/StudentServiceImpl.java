package com.project.service;

import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import com.project.model.Student;
import com.project.repository.StudentRepository;

@Service
public class StudentServiceImpl implements StudentService{
	
	private StudentRepository studentRepository;
	
	@Autowired //adnotację można pomijać, jeżeli nie ma kilku wersji konstruktora
	public StudentServiceImpl(StudentRepository studentRepository) {
	this.studentRepository = studentRepository;
	}
	
	@Override
	public Optional<Student> getStudent(Integer studentId) {
	return studentRepository.findById(studentId);
	}
	
	@Override
	public Student setStudent(Student student) {
		return studentRepository.save(student);
	}
	
	@Override
	public void deleteStudent(Integer studentId) {
	//TODO
	}
	
	
	@Override
	public Page<Student> getStudenci(Pageable pageable) {
		return studentRepository.findAll(pageable);
	}
	@Override
	public Page<Student> searchByImie(String imie, Pageable pageable) {
	//TODO
	return null;
	}

	@Override
	public Optional<Student> searchByEmail(String email) {
		return studentRepository.findByEmail(email);
	}
	
	
	
}