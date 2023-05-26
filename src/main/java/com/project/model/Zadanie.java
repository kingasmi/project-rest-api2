package com.project.model;

import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Entity
@Table(name="zadanie")
public class Zadanie {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name="zadanie_id")
	private Integer zadanieId;
	
	@NotBlank(message = "Pole nazwa nie może być puste!")
	@Size(min = 3, max = 50, message = "Nazwa musi zawierać od {min} do {max} znaków!")
	@Column(nullable = false, length = 50)
	private String nazwa;
	
	@Column(nullable = false)
	private Integer kolejnosc;
	
	@Size(min = 0, max = 1000, message = "Opis musi zawierać od {min} do {max} znaków!")
	@Column(length = 1000)
	private String opis;
	
	@CreationTimestamp
	@NotNull(message = "Pole dataczas utworzenia nie może być puste!")
	@Column(name = "dataczas_dodania", nullable = false, updatable = false)
	private LocalDateTime dataCzasDodania;
	
	@ManyToOne
	@JoinColumn(name = "projekt_id")
	private Projekt projekt;
	
	
	public Zadanie() {
		super();
	}

	public Zadanie(String nazwa, Integer kolejnosc, String opis) {
		super();
		this.nazwa = nazwa;
		this.kolejnosc = kolejnosc;
		this.opis = opis;
	}

	public Integer getZadanieId() {
		return zadanieId;
	}

	public void setZadanieId(Integer zadanieId) {
		this.zadanieId = zadanieId;
	}

	public Projekt getProjekt() {
		return projekt;
	}

	public void setProjekt(Projekt projekt) {
		this.projekt = projekt;
	}

	public String getNazwa() {
		return nazwa;
	}

	public void setNazwa(String nazwa) {
		this.nazwa = nazwa;
	}

	public Integer getKolejnosc() {
		return kolejnosc;
	}

	public void setKolejnosc(Integer kolejnosc) {
		this.kolejnosc = kolejnosc;
	}

	public String getOpis() {
		return opis;
	}

	public void setOpis(String opis) {
		this.opis = opis;
	}

	public LocalDateTime getDataCzasDodania() {
		return dataCzasDodania;
	}

	public void setDataCzasDodania(LocalDateTime dataCzasDodania) {
		this.dataCzasDodania = dataCzasDodania;
	}

	
}