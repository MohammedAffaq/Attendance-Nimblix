package com.nimblix.attendance.controller;

import java.io.IOException;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import com.nimblix.attendance.dto.request.LoginRequest;
import com.nimblix.attendance.dto.request.RegisterRequest;
import com.nimblix.attendance.dto.response.LoginResponse;
import com.nimblix.attendance.entity.CustomUserDetails;
import com.nimblix.attendance.entity.Role;
import com.nimblix.attendance.entity.User;
import com.nimblix.attendance.repository.UserRepository;
import com.nimblix.attendance.security.JwtService;
import com.nimblix.attendance.service.FileStorageService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

//@CrossOrigin(origins = "https://nimblix.netlify.app")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

	private final AuthenticationManager authenticationManager;
	private final JwtService jwtService;
	private final UserRepository userRepository;
	private final FileStorageService storage;

	// --- Login ---
	@PostMapping("/login")
	public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest request) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						request.getEmail(),
						request.getPassword()
				)
		);

		CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

		// Generate JWT (already includes role internally if your JwtService supports it)
		String token = jwtService.generateToken(
				userDetails.getUsername(),
				userDetails.getRole()
		);

		// Extract role as String
		String role = userDetails.getRole().name();

		return ResponseEntity.ok(
				new LoginResponse(
						token,
						jwtService.getExpirationSeconds(),
						role   // ✅ send role in response
				)
		);
	}

	// --- Register ---
	@PostMapping(value = "/register", consumes = "multipart/form-data")
	public ResponseEntity<String> register(@RequestPart("data") @Valid RegisterRequest request,
			@RequestPart("photo") MultipartFile photo) {

		if (userRepository.existsByEmailIgnoreCase(request.getEmail())) {
			throw new IllegalStateException("Email already registered");
		}

		validatePhoto(photo);

		// Create user
		User user = new User();
		user.setEmail(request.getEmail());
		user.setName(request.getName());
		user.setPassword(passwordEncoder().encode(request.getPassword()));
		user.setRole(request.getRole() != null ? Role.valueOf(request.getRole()) : Role.EMPLOYEE);
		user.setEnabled(true);
		user.setLocked(false);

		user = userRepository.save(user);

		// Save profile photo
		String filename = "user_" + user.getId() + ".jpg";
		String photoPath = null;
		try {
			photoPath = storage.save(photo, "users", filename);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		user.setPhotoPath(photoPath);
		userRepository.save(user);

		return ResponseEntity.ok("User registered successfully");
	}

	// --- Helper: validate photo ---
	private void validatePhoto(MultipartFile photo) {
		if (photo == null || photo.isEmpty()) {
			throw new IllegalStateException("Profile photo is required");
		}
		if (!photo.getContentType().startsWith("image/")) {
			throw new IllegalStateException("Only image files allowed");
		}
		if (photo.getSize() > 5 * 1024 * 1024) {
			throw new IllegalStateException("Max photo size is 5MB");
		}
	}

	// --- Password encoder ---
	private org.springframework.security.crypto.password.PasswordEncoder passwordEncoder() {
		return new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
	}
}
