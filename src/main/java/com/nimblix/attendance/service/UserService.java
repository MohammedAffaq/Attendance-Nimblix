package com.nimblix.attendance.service;

import java.util.List;
import java.util.Map;

import org.springframework.web.multipart.MultipartFile;

import com.nimblix.attendance.entity.CreateEmployeeRequest;
import com.nimblix.attendance.entity.UserResponse;

public interface UserService {

	void createEmployee(CreateEmployeeRequest request, MultipartFile photo);

	void updateEmployee(Long id, com.nimblix.attendance.entity.UpdateEmployeeRequest request, MultipartFile photo);

	void updateStatus(Long userId, boolean enabled);

	void updateLock(Long userId, boolean locked);

	List<UserResponse> getAllEmployees();

	Map<String, Object> bulkUploadEmployees(MultipartFile file);

	void deleteEmployee(Long id);
}
