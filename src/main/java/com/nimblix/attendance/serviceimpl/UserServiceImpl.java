package com.nimblix.attendance.serviceimpl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import com.nimblix.attendance.entity.CreateEmployeeRequest;
import com.nimblix.attendance.entity.Role;
import com.nimblix.attendance.entity.UpdateEmployeeRequest;
import com.nimblix.attendance.entity.User;
import com.nimblix.attendance.entity.UserResponse;
import com.nimblix.attendance.exception.BadRequestException;
import com.nimblix.attendance.repository.AttendanceRepository;
import com.nimblix.attendance.repository.UserRepository;
import com.nimblix.attendance.service.FileStorageService;
import com.nimblix.attendance.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class UserServiceImpl implements UserService {

	private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

	private final UserRepository userRepo;
	private final AttendanceRepository attendanceRepo;
	private final FileStorageService storage;
	private final PasswordEncoder passwordEncoder;

	// ============================
	// CREATE EMPLOYEE (single)
	// ============================
	@Transactional
	public void createEmployee(CreateEmployeeRequest request, MultipartFile photo) {

		if (userRepo.existsByEmailIgnoreCase(request.getEmail())) {
			throw new BadRequestException("Email already exists");
		}

		String photoPath = null;
		if (photo != null && !photo.isEmpty()) {
			try {
				photoPath = storage.save(
						photo,
						"users",
						"user_" + System.currentTimeMillis() + ".jpg");
			} catch (IOException e) {
				throw new RuntimeException("Photo upload failed", e);
			}
		}

		User user = new User();
		user.setEmployeeId(request.getEmployeeId());
		user.setName(request.getName());
		user.setEmail(request.getEmail());
		user.setPassword(passwordEncoder.encode(request.getPassword()));
		user.setRole(request.getRole() != null ? request.getRole() : Role.EMPLOYEE);
		user.setPhotoPath(photoPath);
		user.setEnabled(true);

		userRepo.save(user);
	}

	// ============================
	// BULK UPLOAD EMPLOYEES (Excel)
	// ============================
	@Override
	@Transactional
	public Map<String, Object> bulkUploadEmployees(MultipartFile file) {

		int totalRows = 0;
		int successCount = 0;
		int failCount = 0;
		List<String> errors = new ArrayList<>();

		try (Workbook workbook = new XSSFWorkbook(file.getInputStream())) {
			Sheet sheet = workbook.getSheetAt(0);
			int lastRow = sheet.getLastRowNum();

			// Collect users to batch-save for performance
			List<User> toSave = new ArrayList<>();

			for (int i = 1; i <= lastRow; i++) { // skip header row (i=0)
				Row row = sheet.getRow(i);
				if (isRowBlank(row))
					continue;

				totalRows++;
				int rowNum = i + 1; // 1-based for user-facing messages

				try {
					String employeeId = getCellString(row, 0);
					String name = getCellString(row, 1);
					String email = getCellString(row, 2);
					String password = getCellString(row, 3);

					// ── Validate fields ──────────────────────────────
					if (employeeId.isBlank()) {
						errors.add("Row " + rowNum + ": Employee ID is blank");
						failCount++;
						continue;
					}
					if (name.isBlank()) {
						errors.add("Row " + rowNum + ": Name is blank");
						failCount++;
						continue;
					}
					if (email.isBlank()) {
						errors.add("Row " + rowNum + ": Email is blank");
						failCount++;
						continue;
					}
					if (!EMAIL_PATTERN.matcher(email).matches()) {
						errors.add("Row " + rowNum + ": Invalid email format — " + email);
						failCount++;
						continue;
					}
					if (password.isBlank()) {
						errors.add("Row " + rowNum + ": Password is blank");
						failCount++;
						continue;
					}

					// ── Duplicate checks ─────────────────────────────
					if (userRepo.existsByEmailIgnoreCase(email)) {
						errors.add("Row " + rowNum + ": Duplicate email — " + email);
						failCount++;
						continue;
					}
					if (userRepo.existsByEmployeeIdIgnoreCase(employeeId)) {
						errors.add("Row " + rowNum + ": Duplicate employee ID — " + employeeId);
						failCount++;
						continue;
					}

					// ── Build user entity ─────────────────────────────
					CreateEmployeeRequest req = new CreateEmployeeRequest();
					req.setEmployeeId(employeeId);
					req.setName(name);
					req.setEmail(email);
					req.setPassword(password);
					req.setRole(Role.EMPLOYEE);

					log.info("Creating employee with email: {}", email);

					try {
						createEmployee(req, null);
						successCount++;
					} catch (Exception ex) {
						log.error("Error saving row {}: {}", rowNum, ex.getMessage());
						errors.add("Row " + rowNum + ": Failed to save — " + ex.getMessage());
						failCount++;
					}

				} catch (Exception ex) {
					log.error("Error processing row {}: {}", rowNum, ex.getMessage());
					errors.add("Row " + rowNum + ": Unexpected error — " + ex.getMessage());
					failCount++;
				}
			}

		} catch (IOException e) {
			throw new BadRequestException("Failed to read Excel file: " + e.getMessage());
		}

		Map<String, Object> result = new HashMap<>();
		result.put("totalRows", totalRows);
		result.put("successCount", successCount);
		result.put("failCount", failCount);
		result.put("errors", errors);
		return result;
	}

	// ============================
	// UPDATE EMPLOYEE
	// ============================
	@Transactional
	@Override
	public void updateEmployee(Long id, UpdateEmployeeRequest request, MultipartFile photo) {
		User user = userRepo.findById(id).orElseThrow(() -> new BadRequestException("Employee not found"));

		if (userRepo.existsByEmailIgnoreCaseAndIdNot(request.getEmail(), id)) {
			throw new BadRequestException("Email already exists");
		}

		if (userRepo.existsByEmployeeIdIgnoreCaseAndIdNot(request.getEmployeeId(), id)) {
			throw new BadRequestException("Employee ID already exists");
		}

		if (photo != null && !photo.isEmpty()) {
			try {
				validatePhoto(photo);
				String photoPath = storage.save(
						photo,
						"users",
						"user_" + System.currentTimeMillis() + ".jpg");
				user.setPhotoPath(photoPath);
			} catch (IOException e) {
				throw new RuntimeException("Photo upload failed", e);
			}
		}

		user.setEmployeeId(request.getEmployeeId());
		user.setName(request.getName());
		user.setEmail(request.getEmail());
		if (request.getRole() != null) {
			user.setRole(request.getRole());
		}

		if (request.getPassword() != null && !request.getPassword().trim().isEmpty()) {
			user.setPassword(passwordEncoder.encode(request.getPassword()));
		}

		userRepo.save(user);
	}

	// ============================
	// DELETE EMPLOYEE
	// ============================
	@Transactional
	@Override
	public void deleteEmployee(Long id) {
		User user = userRepo.findById(id).orElseThrow(() -> new BadRequestException("Employee not found"));
		attendanceRepo.deleteByUserId(id);
		userRepo.delete(user);
	}

	// ============================
	// STATUS / LOCK
	// ============================
	@Override
	public void updateStatus(Long userId, boolean enabled) {
		User user = userRepo.findById(userId).orElseThrow(() -> new IllegalStateException("User not found"));
		user.setEnabled(enabled);
	}

	@Override
	public void updateLock(Long userId, boolean locked) {
		User user = userRepo.findById(userId).orElseThrow(() -> new IllegalStateException("User not found"));
		user.setLocked(locked);
	}

	// ============================
	// GET ALL EMPLOYEES
	// ============================
	@Override
	public List<UserResponse> getAllEmployees() {
		return userRepo.findAll()
				.stream()
				.map(this::mapToResponse)
				.toList();
	}

	// ============================
	// HELPERS
	// ============================
	private UserResponse mapToResponse(User user) {
		UserResponse r = new UserResponse();
		r.setId(user.getId());
		r.setEmployeeId(user.getEmployeeId());
		r.setName(user.getName());
		r.setEmail(user.getEmail());
		r.setRole(user.getRole());
		r.setEnabled(user.isEnabled());
		r.setLocked(user.isLocked());
		r.setPhotoPath(user.getPhotoPath());
		return r;
	}

	/** Returns true if all cells in the row are null/blank. */
	private boolean isRowBlank(Row row) {
		if (row == null)
			return true;
		for (int c = 0; c < 4; c++) {
			Cell cell = row.getCell(c);
			if (cell != null && cell.getCellType() != CellType.BLANK) {
				String val = getCellString(row, c);
				if (!val.isBlank())
					return false;
			}
		}
		return true;
	}

	/** Safely reads a cell as a trimmed String regardless of cell type. */
	private String getCellString(Row row, int col) {
		Cell cell = row.getCell(col);
		if (cell == null) {
			return "";
		}

		CellType type = cell.getCellType();
		if (type == CellType.FORMULA) {
			type = cell.getCachedFormulaResultType();
		}

		if (type == CellType.NUMERIC) {
			double val = cell.getNumericCellValue();
			if (val == Math.floor(val) && !Double.isInfinite(val)) {
				return java.math.BigDecimal.valueOf(val).toPlainString();
			}
			return String.valueOf(val);
		} else if (type == CellType.STRING) {
			return cell.getStringCellValue().trim();
		}

		return new org.apache.poi.ss.usermodel.DataFormatter().formatCellValue(cell).trim();
	}

	private void validatePhoto(MultipartFile photo) {
		if (photo == null || photo.isEmpty()) {
			throw new IllegalStateException("Photo is required");
		}
		if (!photo.getContentType().startsWith("image/")) {
			throw new IllegalStateException("Only image files are allowed");
		}
		if (photo.getSize() > 5 * 1024 * 1024) {
			throw new IllegalStateException("Max photo size is 5MB");
		}
	}
}
