package com.project.controller;

import java.net.URI;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import com.project.model.Student;
import com.project.service.StudentService;

		//dzięki adnotacji @RestController klasa jest traktowana jako zarządzany
@RestController 	// przez kontener Springa REST-owy kontroler obsługujący sieciowe żądania
@RequestMapping("/api") // adnotacja @RequestMapping umieszczona w tym miejscu pozwala definiować

public class StudentRestController { // cześć wspólną adresu, wstawianą przed wszystkimi poniższymi ścieżkami

	private StudentService studentService; //serwis jest automatycznie wstrzykiwany poprzez konstruktor
	@Autowired
	public StudentRestController(StudentService studentService) {
		this.studentService = studentService;
	}
	
	//PRZED KAŻDĄ Z PONIŻSZYCH METOD JEST UMIESZCZONA ADNOTACJA (@GetMapping, PostMapping, ... ), KTÓRA OKREŚLA
	//RODZAJ METODY HTTP, A TAKŻE ADRES I PARAMETRY ŻĄDANIA
	
	//Przykład żądania wywołującego metodę: GET http://localhost:8080/api/studenci/1
	@GetMapping("/studenci/{studentId}")ResponseEntity<Student> getStudent(@PathVariable Integer studentId) {// @PathVariable oznacza, że wartość
	return ResponseEntity.of(studentService.getStudent(studentId)); // parametru przekazywana jest w ścieżce
	}
		
		//@Valid włącza automatyczną walidację na podstawie adnotacji zawartych
		//w modelu np. NotNull, Size, NotEmpty itd. (z jakarta.validation.constraints.*)
	
	@PostMapping(path = "/studenci")
	ResponseEntity<Void> createStudent(@Valid @RequestBody Student student) {// @RequestBody oznacza, że dane
		//studentu (w formacie JSON) są
		Student createdStudent = studentService.setStudent(student); // przekazywane w ciele żądania
		URI location = ServletUriComponentsBuilder.fromCurrentRequest() // link wskazujący utworzony student
				.path("/{studentId}").buildAndExpand(createdStudent.getStudentId()).toUri();
		
		return ResponseEntity.created(location).build(); // zwracany jest kod odpowiedzi 201 - Created
	} 								// z linkiem location w nagłówku
	
	@PutMapping("/studenci/{studentId}")
	public ResponseEntity<Void> updateStudent(@Valid @RequestBody Student student,
		@PathVariable Integer studentId) {
		return studentService.getStudent(studentId)
			.map(p -> {
				studentService.setStudent(student);
				return new ResponseEntity<Void>(HttpStatus.OK); // 200 (można też zwracać 204 - No content)
			})
		.orElseGet(() -> ResponseEntity.notFound().build()); // 404 - Not found
	}
	
	@DeleteMapping("/studenci/{studentId}")
	public ResponseEntity<Void> deleteStudent(@PathVariable Integer studentId) {
		return studentService.getStudent(studentId).map(p -> {
			studentService.deleteStudent(studentId);
			return new ResponseEntity<Void>(HttpStatus.OK); // 200
		}).orElseGet(() -> ResponseEntity.notFound().build()); // 404 - Not found
	}
	
	//Przykład żądania wywołującego metodę: http://localhost:8080/api/studenci?page=0&size=10&sort=nazwa,desc
	@GetMapping(value = "/studenci")
	Page<Student> getStudenci(Pageable pageable) { // @RequestHeader HttpHeaders headers – jeżeli potrzebny
		return studentService.getStudenci(pageable); // byłby nagłówek, wystarczy dodać drugą zmienną z adnotacją
	}
	
	//Przykład żądania wywołującego metodę: GET http://localhost:8080/api/studenci?nazwa=webowa
	//Metoda zostanie wywołana tylko, gdy w żądaniu będzie przesyłana wartość parametru nazwa.
	@GetMapping(value = "/studenci", params="imie")
	Page<Student> getstudenciByImie(@RequestParam String imie, Pageable pageable) {
		return studentService.searchByImie(imie, pageable);
	}
}