package id.ac.ui.cs.advprog.b13.hiringgo.auth.repository;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.Role;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager; // Opsional, bisa berguna

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest // Anotasi inti untuk tes integrasi JPA
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    // TestEntityManager adalah alternatif dari langsung menggunakan repository untuk setup data,
    // ia menyediakan metode flush dan find yang berguna dalam beberapa skenario tes.
    // Untuk tes sederhana ini, userRepository.save() sudah cukup.
    // @Autowired
    // private TestEntityManager entityManager;

    private User user1;
    private User user2;

    @BeforeEach
    void setUp() {
        // Bersihkan data sebelum setiap tes (meskipun @DataJpaTest melakukan rollback, ini untuk kejelasan)
        // userRepository.deleteAll(); // Bisa juga, tapi rollback sudah cukup

        user1 = User.builder()
                .namaLengkap("User Satu")
                .email("user.satu@example.com")
                .password("hashedPassword1")
                .role(Role.MAHASISWA)
                .nim("1111111111")
                .build();

        user2 = User.builder()
                .namaLengkap("User Dua")
                .email("user.dua@example.com")
                .password("hashedPassword2")
                .role(Role.DOSEN)
                .nip("2222222222")
                .build();

        // Simpan beberapa data awal jika diperlukan oleh banyak tes
        // userRepository.save(user1);
        // userRepository.save(user2);
    }

    @AfterEach
    void tearDown() {
        // @DataJpaTest sudah melakukan rollback, jadi ini biasanya tidak perlu.
        // userRepository.deleteAll();
    }

    @Test
    void testSaveAndFindById() {
        // Arrange
        User savedUser = userRepository.save(user1);
        assertNotNull(savedUser.getId()); // Pastikan ID di-generate

        // Act
        Optional<User> foundUserOpt = userRepository.findById(savedUser.getId());

        // Assert
        assertTrue(foundUserOpt.isPresent());
        User foundUser = foundUserOpt.get();
        assertEquals(user1.getEmail(), foundUser.getEmail());
        assertEquals(user1.getNamaLengkap(), foundUser.getNamaLengkap());
        assertEquals(user1.getRole(), foundUser.getRole());
    }

    @Test
    void testFindByEmail_UserExists() {
        // Arrange
        userRepository.save(user1);

        // Act
        Optional<User> foundUserOpt = userRepository.findByEmail("user.satu@example.com");

        // Assert
        assertTrue(foundUserOpt.isPresent());
        assertEquals(user1.getNamaLengkap(), foundUserOpt.get().getNamaLengkap());
    }

    @Test
    void testFindByEmail_UserDoesNotExist() {
        // Act
        Optional<User> foundUserOpt = userRepository.findByEmail("non.existent@example.com");

        // Assert
        assertFalse(foundUserOpt.isPresent());
    }

    @Test
    void testExistsByEmail_UserExists() {
        // Arrange
        userRepository.save(user1);

        // Act
        boolean exists = userRepository.existsByEmail("user.satu@example.com");

        // Assert
        assertTrue(exists);
    }

    @Test
    void testExistsByEmail_UserDoesNotExist() {
        // Act
        boolean exists = userRepository.existsByEmail("non.existent@example.com");

        // Assert
        assertFalse(exists);
    }

    @Test
    void testExistsByNim_UserExists() {
        // Arrange
        userRepository.save(user1); // user1 memiliki NIM

        // Act
        boolean exists = userRepository.existsByNim("1111111111");

        // Assert
        assertTrue(exists);
    }

    @Test
    void testExistsByNim_UserDoesNotExist() {
        // Act
        boolean exists = userRepository.existsByNim("0000000000");

        // Assert
        assertFalse(exists);
    }

    @Test
    void testExistsByNim_UserHasNoNim() {
        // Arrange
        // user1 memiliki NIM "1111111111"
        // user2 adalah dosen, NIM-nya null saat dibuat
        userRepository.save(user1);
        userRepository.save(user2);

        // Act
        boolean existsForUser1Nim = userRepository.existsByNim("1111111111");
        boolean existsForNonExistentNim = userRepository.existsByNim("0000000000"); // NIM yang pasti tidak ada
        boolean existsForNullNimQuery = userRepository.existsByNim(null); // Mengecek apakah ada user dengan NIM NULL

        // Assert
        assertTrue(existsForUser1Nim, "User1 dengan NIM 1111111111 seharusnya ada");
        assertFalse(existsForNonExistentNim, "User dengan NIM 0000000000 seharusnya tidak ada");

        // Karena kita menyimpan user2 yang NIM-nya null, maka query untuk NIM IS NULL akan true
        assertTrue(existsForNullNimQuery, "Seharusnya ada user (user2) yang NIM-nya NULL");
    }


    @Test
    void testSaveMultipleUsers() {
        // Arrange
        User savedUser1 = userRepository.save(user1);
        User savedUser2 = userRepository.save(user2);

        // Act
        long count = userRepository.count();

        // Assert
        assertEquals(2, count);
        assertNotNull(savedUser1.getId());
        assertNotNull(savedUser2.getId());
    }

    @Test
    void testDeleteUser() {
        // Arrange
        User savedUser = userRepository.save(user1);
        Long userId = savedUser.getId();

        // Act
        userRepository.deleteById(userId);
        Optional<User> deletedUserOpt = userRepository.findById(userId);

        // Assert
        assertFalse(deletedUserOpt.isPresent());
    }
}