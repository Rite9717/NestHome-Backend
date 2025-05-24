package com.nesthome.controller;

import com.nesthome.entity.serviceEntity;
import com.nesthome.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(userService.findAllUsers());
    }

    @PostMapping("/assign-role")
    public ResponseEntity<?> assignRole(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String roleName = request.get("role");
        userService.assignRole(username, roleName);
        return ResponseEntity.ok(Map.of("message", "Role assigned successfully"));
    }

    @DeleteMapping("/delete")
    public ResponseEntity<?> delete(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        userService.delete(username);
        return ResponseEntity.ok("user deleted successfully");
    }

    @PostMapping("/createservice")
    public ResponseEntity<?> createservice(@RequestBody Map<String, Object> request) {
        String servicename = (String) request.get("servicename");
        double price = Double.parseDouble(request.get("price").toString());
        if (userService.findByService(servicename).isPresent()) {
            return ResponseEntity.badRequest().body("Service already exists");
        }
        serviceEntity service = new serviceEntity();
        service.setName(servicename);
        service.setPrice(price);
        userService.saveService(service);
        return ResponseEntity.ok("Service Created Successfully");
    }

    @GetMapping("/dashboard-stats")
    public ResponseEntity<?> getDashboardStats() {
        int totalUsers = userService.total_no_of_user();
        int professionals = userService.total_no_of_professional();
        Map<String, Integer> stats = new HashMap<>();
        stats.put("totalUsers", totalUsers);
        stats.put("professionals", professionals);
        return ResponseEntity.ok(stats);
    }
}
