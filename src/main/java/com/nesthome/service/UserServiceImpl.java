package com.nesthome.service;

import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.nesthome.entity.Role;
import com.nesthome.entity.User;
import com.nesthome.repository.RoleRepository;
import com.nesthome.repository.UserRepository;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userrepository;
    private final RoleRepository rolerepository;
    private final PasswordEncoder passwordEncoder;
    public UserServiceImpl(UserRepository userrepository, RoleRepository rolerepository,PasswordEncoder passwordEncoder) {
        this.userrepository = userrepository;
        this.rolerepository = rolerepository;
        this.passwordEncoder=passwordEncoder;
    }

    @Override
    public User saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userrepository.save(user);
    }

    @Override
    public User findByUsername(String username) {
        return userrepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User Not Found"));
    }

    @Override
    public List<User> findAllUsers() {
        return userrepository.findAll();
    }

    @Override
    public Boolean checkIfUserExists(String username) {
        return userrepository.existsByUsername(username);
    }

    @Override
    public Boolean checkIfEmailExists(String email) {
        return userrepository.existsByEmail(email);
    }

	@Override
	public void assignRole(String username, String roleName) {
		User user = findByUsername(username);
        Role role = rolerepository.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Role not found"));
        user.getRoles().add(role);
        userrepository.save(user);
		
	}
}
