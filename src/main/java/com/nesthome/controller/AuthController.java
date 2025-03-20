package com.nesthome.controller;

import com.nesthome.entity.Role;
import com.nesthome.entity.User;
import com.nesthome.repository.RoleRepository;
import com.nesthome.service.UserService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:3000")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final RoleRepository rolerepository;
    
    public AuthController(AuthenticationManager authenticationManager, UserService userService,RoleRepository rolerepository) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.rolerepository=rolerepository;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginRequest, 
                                  HttpServletRequest request,
                                  HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.get("username"),
                            loginRequest.get("password")
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            HttpSession session = request.getSession(true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
            Cookie sessionCookie = new Cookie("JSESSIONID", session.getId());
            sessionCookie.setPath("/");
            sessionCookie.setHttpOnly(true);
            sessionCookie.setMaxAge(-1);
            response.addCookie(sessionCookie);
            
            return ResponseEntity.ok(Map.of(
                "message", "Login successful", 
                "user", authentication.getName(),
                "authorities", authentication.getAuthorities().toString(),
                "sessionId", session.getId()
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Authentication failed: " + e.getMessage()));
        }
    }
    
    @GetMapping("/session-invalid")
    public ResponseEntity<?> sessionInvalid() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("message", "Session invalid or expired"));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, Object> requestBody) {
        try {
            String username = (String) requestBody.get("username");
            String password = (String) requestBody.get("password");
            String email = (String) requestBody.get("email");
            if (userService.checkIfUserExists(username)) {
                return ResponseEntity.badRequest().body(Map.of("message", "Username already exists"));
            }
            
            User user = new User();
            user.setUsername(username);
            user.setPassword(password);
            user.setEmail(email);
            
            Set<Role> roles = new HashSet<>();
            if (requestBody.containsKey("role")) {
                List<Map<String, String>> roleList = (List<Map<String, String>>) requestBody.get("role");
                for (Map<String, String> roleMap : roleList) {
                    String roleName = roleMap.get("name");
                    Role found = rolerepository.findByName(roleName)
                        .orElseThrow(() -> new RuntimeException("Role Not Found: " + roleName));
                    roles.add(found);
                }
            }
            
            user.setRoles(roles);
            userService.saveUser(user);
            
            return ResponseEntity.ok(Map.of(
                "message", "User registered successfully",
                "username", user.getUsername(),
                "roles", roles.stream().map(Role::getName).collect(Collectors.toList())
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "message", "Registration failed",
                "error", e.getMessage()
            ));
        }
    }

    /*@PostMapping("/logout")
    public ResponseEntity<?> logout() {
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }*/
}
