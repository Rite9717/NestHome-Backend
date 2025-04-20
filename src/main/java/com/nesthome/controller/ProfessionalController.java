package com.nesthome.controller;

import com.nesthome.entity.User;
import com.nesthome.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/professional")
@PreAuthorize("hasRole('PROFESSIONAL')")
public class ProfessionalController {

    private final UserService userService;

    public ProfessionalController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/dashboard")
    public ResponseEntity<?> professionalDashboard() {
        return ResponseEntity.ok(Map.of("message", "Welcome, Professional!"));
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfessionalProfile(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body("Not authenticated");
        }

        String username = authentication.getName();
        User user = userService.findByUsername(username);

        return ResponseEntity.ok(user);
    }
}
