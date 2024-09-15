package com.springsecurity.client.repository;

import com.springsecurity.client.entity.User;
import com.springsecurity.client.model.UserModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    User findByEmail(String email);
}
