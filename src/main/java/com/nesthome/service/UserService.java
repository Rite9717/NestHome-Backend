package com.nesthome.service;

import java.util.List;

import com.nesthome.entity.User;

public interface UserService {

	User saveUser(User user);
	User findByUsername(String username);
	List<User> findAllUsers();
	void assignRole(String username, String roleName);
	Boolean checkIfUserExists(String username);
	Boolean checkIfEmailExists(String email);
}
