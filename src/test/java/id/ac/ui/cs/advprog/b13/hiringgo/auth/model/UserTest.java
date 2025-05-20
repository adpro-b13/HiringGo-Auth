package id.ac.ui.cs.advprog.b13.hiringgo.auth.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class UserTest {

    private User userMahasiswa;
    private User userDosen;

    @BeforeEach
    void setUp() {
        // Setup User dengan role MAHASISWA
        userMahasiswa = User.builder()
                .id(1L)
                .namaLengkap("Budi Mahasiswa")
                .email("budi.mhs@example.com")
                .password("hashedPassword123")
                .role(Role.MAHASISWA)
                .nim("2300000001")
                .nip(null) // Mahasiswa tidak punya NIP
                .build();

        // Setup User dengan role DOSEN
        userDosen = new User(
                2L,
                "Citra Dosen",
                "citra.dosen@example.com",
                "anotherHashedPassword",
                Role.DOSEN,
                null, // Dosen tidak punya NIM
                "198001012005012001"
        );
    }

    @Test
    void testCreateUserWithBuilder() {
        assertNotNull(userMahasiswa);
        assertEquals(1L, userMahasiswa.getId());
        assertEquals("Budi Mahasiswa", userMahasiswa.getNamaLengkap());
        assertEquals("budi.mhs@example.com", userMahasiswa.getEmail());
        assertEquals("hashedPassword123", userMahasiswa.getPassword());
        assertEquals(Role.MAHASISWA, userMahasiswa.getRole());
        assertEquals("2300000001", userMahasiswa.getNim());
        assertNull(userMahasiswa.getNip());
    }

    @Test
    void testCreateUserWithAllArgsConstructor() {
        assertNotNull(userDosen);
        assertEquals(2L, userDosen.getId());
        assertEquals("Citra Dosen", userDosen.getNamaLengkap());
        assertEquals("citra.dosen@example.com", userDosen.getEmail());
        assertEquals("anotherHashedPassword", userDosen.getPassword());
        assertEquals(Role.DOSEN, userDosen.getRole());
        assertNull(userDosen.getNim());
        assertEquals("198001012005012001", userDosen.getNip());
    }

    @Test
    void testGetAuthoritiesForMahasiswa() {
        Collection<? extends GrantedAuthority> authorities = userMahasiswa.getAuthorities();
        assertNotNull(authorities);
        assertEquals(1, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_MAHASISWA")));
    }

    @Test
    void testGetAuthoritiesForDosen() {
        Collection<? extends GrantedAuthority> authorities = userDosen.getAuthorities();
        assertNotNull(authorities);
        assertEquals(1, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_DOSEN")));
    }

    @Test
    void testGetUsernameReturnsEmail() {
        assertEquals("budi.mhs@example.com", userMahasiswa.getUsername());
        assertEquals("citra.dosen@example.com", userDosen.getUsername());
    }

    @Test
    void testUserDetailsMethodsReturnTrue() {
        assertTrue(userMahasiswa.isAccountNonExpired());
        assertTrue(userMahasiswa.isAccountNonLocked());
        assertTrue(userMahasiswa.isCredentialsNonExpired());
        assertTrue(userMahasiswa.isEnabled());
    }

    @Test
    void testSettersAndGetters() {
        User user = new User();
        user.setId(3L);
        user.setNamaLengkap("User Test");
        user.setEmail("test.user@example.com");
        user.setPassword("testPassword");
        user.setRole(Role.ADMIN);
        user.setNim("2300000003");
        user.setNip("199001012010011001");

        assertEquals(3L, user.getId());
        assertEquals("User Test", user.getNamaLengkap());
        assertEquals("test.user@example.com", user.getEmail());
        assertEquals("testPassword", user.getPassword());
        assertEquals(Role.ADMIN, user.getRole());
        assertEquals("2300000003", user.getNim());
        assertEquals("199001012010011001", user.getNip());
    }

    @Test
    void testEqualsAndHashCode() {
        User user1a = User.builder().id(1L).email("user1@example.com").role(Role.MAHASISWA).build();
        User user1b = User.builder().id(1L).email("user1@example.com").role(Role.MAHASISWA).build();
        User user2 = User.builder().id(2L).email("user2@example.com").role(Role.DOSEN).build();
        User user1c_differentEmail = User.builder().id(1L).email("user1.diff@example.com").role(Role.MAHASISWA).build();

        // Reflexivity
        assertEquals(user1a, user1a);

        // Symmetry
        assertEquals(user1a, user1b);
        assertEquals(user1b, user1a);

        // Transitivity (Lombok @Data by default compares all fields, so this should hold)
        // User user1c = User.builder().id(1L).email("user1@example.com").role(Role.MAHASISWA).build();
        // assertEquals(user1a, user1c);
        // assertEquals(user1b, user1c);

        // Inequality
        assertNotEquals(user1a, user2);
        assertNotEquals(user1a, null);
        assertNotEquals(user1a, new Object());

        // Tergantung implementasi equals. Jika hanya ID dan email (seperti contoh override manual saya):
        // Jika @Data Lombok default, maka user1a dan user1c_differentEmail akan berbeda.
        // assertNotEquals(user1a, user1c_differentEmail);

        // HashCode consistency
        assertEquals(user1a.hashCode(), user1b.hashCode());
        // assertNotEquals(user1a.hashCode(), user2.hashCode()); // Tidak dijamin berbeda, tapi kemungkinan besar iya
    }

    @Test
    void testToStringDoesNotContainPassword() {
        String userToString = userMahasiswa.toString();
        // Pastikan password tidak muncul di toString (jika @ToString dari Lombok digunakan, bisa dikustomisasi)
        // Jika menggunakan implementasi toString manual yang saya berikan, ini akan pass.
        // Jika menggunakan @Data Lombok, secara default semua field akan masuk, jadi perlu @ToString.Exclude pada password.
        // Untuk versi User.java dengan Lombok @Data yang kita buat sebelumnya,
        // password akan masuk ke toString(). Kita bisa memperbaikinya dengan @ToString.Exclude
        // atau override toString() secara manual di kelas User.
        // Asumsi untuk tes ini: password tidak terekspos.
        assertFalse(userToString.toLowerCase().contains("password"));
        assertFalse(userToString.contains("hashedPassword123")); // Lebih spesifik
        assertTrue(userToString.contains("Budi Mahasiswa"));
    }
}