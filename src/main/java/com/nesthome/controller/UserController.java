package com.nesthome.controller;

import com.nesthome.entity.ServiceRequest;
import com.nesthome.entity.User;
import com.nesthome.entity.serviceEntity;
import com.nesthome.repository.ServiceRepository;
import com.nesthome.repository.ServiceRequestRepository;
import com.nesthome.repository.UserRepository;
import com.nesthome.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
@PreAuthorize("hasRole('USER')")
public class UserController {

    private final UserService userService;
    @Autowired
    private ServiceRequestRepository serviceRequestRepo;
    @Autowired
    private ServiceRepository serviceRepo;
    @Autowired
    private UserRepository userRepo;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        User user = userService.findByUsername(username);
        return ResponseEntity.ok(user);
    }

    @PutMapping("/update")
    public ResponseEntity<?> updateUser(@RequestBody User user) {
        userService.saveUser(user);
        return ResponseEntity.ok(Map.of("message", "Profile updated successfully"));
    }

    @GetMapping("/showservices")
    public ResponseEntity<?> showservices() {
        return ResponseEntity.ok(userService.findAllServices());
    }

    @PostMapping("/request-service")
    public ResponseEntity<?> requestService(@RequestBody Map<String, Object> request, HttpSession session) {
        try {
            Long userId = (Long) session.getAttribute("userId");
            int serviceId = (int) request.get("serviceId");
            User user = userRepo.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            serviceEntity service = serviceRepo.findById(serviceId)
                    .orElseThrow(() -> new RuntimeException("Service not found"));
            ServiceRequest serviceRequest = new ServiceRequest();
            serviceRequest.setUser(user);
            serviceRequest.setService(service);
            serviceRequest.setRequestedAt(LocalDateTime.now());
            serviceRequestRepo.save(serviceRequest);

            return ResponseEntity.ok(Map.of("message", "Service request recorded successfully"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "Failed to record request", "details", e.getMessage()));
        }
    }

    @GetMapping("/get-professionals/{serviceId}")
    public ResponseEntity<?> getProfessionalsByService(@PathVariable int serviceId, HttpSession session) {
        try {
            Long userId = (Long) session.getAttribute("userId");
            if (userId == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "User not logged in"));
            }
            User user = userRepo.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            int pincode = user.getPincode();
            List<User> professionals = userService.findProfessionalsByServiceAndPincode(serviceId, pincode);
            return ResponseEntity.ok(professionals);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Something went wrong", "details", e.getMessage()));
        }
    }
}
