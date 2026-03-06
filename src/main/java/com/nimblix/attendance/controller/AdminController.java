package com.nimblix.attendance.controller;

import java.io.IOException;
import java.time.LocalDate;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimblix.attendance.entity.AttendanceResponse;
import com.nimblix.attendance.entity.AttendanceStatus;
import com.nimblix.attendance.entity.CreateEmployeeRequest;
import com.nimblix.attendance.exception.BadRequestException;
import com.nimblix.attendance.service.AdminAttendanceService;
import com.nimblix.attendance.service.UserService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

	private final UserService userService;

	private final AdminAttendanceService adminAttendanceService;

	// ===============================
	// CREATE EMPLOYEE (POST)
	// ===============================
	@PreAuthorize("hasRole('ADMIN')")
	@PostMapping(value = "/employees", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<?> createEmployee(
			@RequestPart("data") String data,
			@RequestPart(value = "photo", required = false) MultipartFile photo) {

		try {
			ObjectMapper mapper = new ObjectMapper();
			CreateEmployeeRequest request = mapper.readValue(data, CreateEmployeeRequest.class);

			userService.createEmployee(request, photo);
			return ResponseEntity.ok(java.util.Map.of("message", "Employee created successfully"));

		} catch (IOException e) {
			throw new BadRequestException("Invalid request data");
		}
	}

	// ===============================
	// BULK UPLOAD EMPLOYEES (POST)
	// ===============================
	@PreAuthorize("hasRole('ADMIN')")
	@PostMapping(value = "/employees/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<?> uploadEmployees(
			@RequestParam("file") MultipartFile file) {

		if (file == null || file.isEmpty()) {
			throw new BadRequestException("File is empty");
		}

		String originalFilename = file.getOriginalFilename();
		if (originalFilename == null || !originalFilename.toLowerCase().endsWith(".xlsx")) {
			throw new BadRequestException("Only .xlsx files are accepted");
		}

		if (file.getSize() > 10 * 1024 * 1024) { // 10 MB limit
			throw new BadRequestException("File size exceeds the 10 MB limit");
		}

		java.util.Map<String, Object> result = userService.bulkUploadEmployees(file);
		return ResponseEntity.ok(result);
	}

	// ===============================
	// UPDATE EMPLOYEE (PUT)
	// ===============================
	@PreAuthorize("hasRole('ADMIN')")
	@PutMapping(value = "/employees/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<?> updateEmployee(
			@PathVariable Long id,
			@RequestPart("data") String data,
			@RequestPart(value = "photo", required = false) MultipartFile photo) {

		try {
			ObjectMapper mapper = new ObjectMapper();
			com.nimblix.attendance.entity.UpdateEmployeeRequest request = mapper.readValue(data,
					com.nimblix.attendance.entity.UpdateEmployeeRequest.class);

			userService.updateEmployee(id, request, photo);
			return ResponseEntity.ok(java.util.Map.of("message", "Employee updated successfully"));

		} catch (IOException e) {
			throw new BadRequestException("Invalid request data");
		}
	}

	// ===============================
	// DELETE EMPLOYEE (DELETE)
	// ===============================
	@PreAuthorize("hasRole('ADMIN')")
	@DeleteMapping("/employees/{id}")
	public ResponseEntity<?> deleteEmployee(@PathVariable Long id) {
		userService.deleteEmployee(id);
		return ResponseEntity.ok(java.util.Map.of("message", "Employee deleted successfully"));
	}

	// ===============================
	// GET ALL EMPLOYEES (GET)
	// ===============================
	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/employees")
	public ResponseEntity<?> getAllEmployees() {
		return ResponseEntity.ok(userService.getAllEmployees());
	}

	// --- All Attendance Records ---
	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/attendance")
	public Page<AttendanceResponse> getAttendanceReport(
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date,
			@RequestParam(required = false) AttendanceStatus status, @RequestParam(defaultValue = "0") int page,
			@RequestParam(defaultValue = "20") int size) {

		Pageable pageable = PageRequest.of(page, size, Sort.by("date").descending());
		return adminAttendanceService.getAttendanceReport(date, status, pageable);
	}

	// --- Late Arrivals ---
	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/attendance/late")
	public Page<AttendanceResponse> getLateArrivals(
			@RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date,
			@RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size) {

		Pageable pageable = PageRequest.of(page, size, Sort.by("checkInTime").ascending());
		return adminAttendanceService.getLateArrivals(date, pageable);
	}

	// --- Early Checkouts ---
	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/attendance/early")
	public Page<AttendanceResponse> getEarlyCheckouts(
			@RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date,
			@RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size) {

		Pageable pageable = PageRequest.of(page, size, Sort.by("checkOutTime").ascending());
		return adminAttendanceService.getEarlyCheckouts(date, pageable);
	}
}
