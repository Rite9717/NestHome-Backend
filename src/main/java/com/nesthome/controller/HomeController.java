package com.nesthome.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.sql.Date;
import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/api/home")
public class HomeController {

    @GetMapping
    public Map<String, Object> home() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return Map.of(
                "username", auth.getName(),
                "roles", auth.getAuthorities()
        );
    }
    
    @GetMapping("/debug/authorities")
    public ResponseEntity<?> getAuthorities() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(Map.of(
            "username", auth.getName(),
            "authorities", auth.getAuthorities()
        ));
    }
    
    @GetMapping("/debug/session")
    public ResponseEntity<?> debugSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        
        if (session == null) {
            return ResponseEntity.ok(Map.of(
                "status", "No session exists",
                "isAuthenticated", SecurityContextHolder.getContext().getAuthentication() != null
            ));
        }
        
        return ResponseEntity.ok(Map.of(
            "sessionId", session.getId(),
            "creationTime", new Date(session.getCreationTime()).toString(),
            "lastAccessedTime", new Date(session.getLastAccessedTime()).toString(),
            "maxInactiveInterval", session.getMaxInactiveInterval(),
            "isNew", session.isNew(),
            "attributeNames", Collections.list(session.getAttributeNames())
        ));
    }
    
    @GetMapping("/session-check")
    public ResponseEntity<?> checkSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        
        if (session == null) {
            return ResponseEntity.ok(Map.of("sessionStatus", "No session exists"));
        }
        
        SecurityContext securityContext = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
        Authentication authentication = securityContext != null ? securityContext.getAuthentication() : null;
        
        return ResponseEntity.ok(Map.of(
            "sessionId", session.getId(),
            "authenticated", authentication != null && authentication.isAuthenticated(),
            "username", authentication != null ? authentication.getName() : "none",
            "authorities", authentication != null ? authentication.getAuthorities().toString() : "none"
        ));
    }
}

