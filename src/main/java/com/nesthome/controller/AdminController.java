package com.nesthome.controller;

import com.nesthome.entity.serviceEntity;
import com.nesthome.service.UserService;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

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
    public ResponseEntity<?> delete(@RequestBody Map<String,String> request)
    {
    	String username=request.get("username");
    	userService.delete(username);
    	return ResponseEntity.ok("user deleted successfully");
    }
    
    @PostMapping("/create_service")
    public ResponseEntity<?> create_service(@RequestBody Map<String, Object> request) {
        String service_name = (String) request.get("service_name");
        double price = Double.parseDouble(request.get("price").toString());

        if (userService.findByService(service_name).isPresent()) {
            return ResponseEntity.badRequest().body("Service already exists");
        }
        serviceEntity service = new serviceEntity();
        service.setName(service_name);
        service.setPrice(price);
        userService.saveService(service);

        return ResponseEntity.ok("Service Created Successfully");
    }

}
