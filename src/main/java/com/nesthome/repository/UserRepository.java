package com.nesthome.repository;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.nesthome.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByUsername(String username); 
    Optional<User> findByEmail(String email); 
    boolean existsByUsername(String username); 
    boolean existsByEmail(String email); 
    
    @Query("SELECT DISTINCT u FROM User u " +
    	       "JOIN u.roles r " +
    	       "JOIN u.servicesProvided s " +
    	       "WHERE r.name = 'PROFESSIONAL' " +
    	       "AND u.pincode = :pincode " +
    	       "AND s.id = :serviceId")
    	List<User> findProfessionalsByPincodeAndService(@Param("pincode") int pincode,
    	                                                 @Param("serviceId") int serviceId);

}
