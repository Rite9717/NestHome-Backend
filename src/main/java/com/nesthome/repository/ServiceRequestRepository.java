package com.nesthome.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nesthome.entity.ServiceRequest;

public interface ServiceRequestRepository extends JpaRepository<ServiceRequest,Long> {

}
