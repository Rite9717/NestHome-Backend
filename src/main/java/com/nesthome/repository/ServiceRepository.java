package com.nesthome.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nesthome.entity.serviceEntity;

public interface ServiceRepository extends JpaRepository<serviceEntity,Integer> {
	
	Optional<serviceEntity> findByName(String username); 
}
