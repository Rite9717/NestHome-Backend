package com.nesthome.service;

import java.util.List;
import java.util.Optional;

import com.nesthome.entity.User;
import com.nesthome.entity.serviceEntity;

public interface UserService {

	User saveUser(User user);
	User findByUsername(String username);
	List<User> findAllUsers();
	void assignRole(String username, String roleName);
	Boolean checkIfUserExists(String username);
	Boolean checkIfEmailExists(String email);
	void delete(String username);
	Optional<serviceEntity> findByService(String service_name);
	serviceEntity saveService(serviceEntity service);
	List<serviceEntity> findAllServices();
	public List<User> findProfessionalsByServiceAndPincode(int serviceId, int pincode);
	public int total_no_of_user();
	public int total_no_of_professional();
}
