package id.ac.ui.cs.advprog.b13.hiringgo.auth.repository;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User; // Import entitas User
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository // Menandakan bahwa interface ini adalah komponen Spring Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
    boolean existsByNim(String nim);
}