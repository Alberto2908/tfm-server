package com.alberto.tfm.vulnerabilidades.repository;

import com.alberto.tfm.vulnerabilidades.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);

    boolean existsByUsername(String username);
    boolean existsByEmail(String email);

    @Query(value = "{ 'email': { $regex: '^?0$', $options: 'i' } }", exists = true)
    boolean existsByEmailIgnoreCase(String email);

    @Query("{ 'email': { $regex: '^?0$', $options: 'i' } }")
    Optional<User> findByEmailIgnoreCase(String email);
}
