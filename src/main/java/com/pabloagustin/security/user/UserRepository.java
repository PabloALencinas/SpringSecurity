package com.pabloagustin.security.user;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {

	// Let's create one method besides the auto generated ones by the JpaRepository (findAll, findById.. etc)
	Optional<User> findByEmail(String email);
}
