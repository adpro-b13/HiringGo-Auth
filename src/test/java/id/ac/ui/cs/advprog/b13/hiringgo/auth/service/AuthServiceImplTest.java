package id.ac.ui.cs.advprog.b13.hiringgo.auth.service;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.RegisterRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.Role;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.repository.UserRepository;
// import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider; // Akan di-mock jika sudah ada

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class) // Mengaktifkan ekstensi Mockito untuk JUnit 5
class AuthServiceImplTest {

    @Mock // Membuat mock object untuk UserRepository
    private UserRepository userRepository;

    @Mock // Membuat mock object untuk PasswordEncoder
    private PasswordEncoder passwordEncoder;

    @Mock // Membuat mock object untuk AuthenticationManager
    private AuthenticationManager authenticationManager;

    // @Mock // Jika JwtTokenProvider sudah ada, mock juga
    // private JwtTokenProvider jwtTokenProvider;

    @InjectMocks // Meng-inject mock objects di atas ke dalam AuthServiceImpl
    private AuthServiceImpl authService;

    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;
    private User user;
    private Authentication authentication;

    @BeforeEach
    void setUp() {
        registerRequest = RegisterRequest.builder()
                .namaLengkap("Test User")
                .email("test@example.com")
                .password("password123")
                .confirmPassword("password123")
                .nim("1234567890")
                .build();

        loginRequest = LoginRequest.builder()
                .email("test@example.com")
                .password("password123")
                .build();

        user = User.builder()
                .id(1L)
                .namaLengkap("Test User")
                .email("test@example.com")
                .password("hashedPassword123") // Password yang sudah di-hash
                .role(Role.MAHASISWA)
                .nim("1234567890")
                .build();

        // Mock Authentication object yang akan dikembalikan oleh AuthenticationManager
        authentication = mock(Authentication.class); // Membuat mock untuk interface Authentication
        SecurityContextHolder.clearContext(); // Pastikan context bersih sebelum tiap tes
    }

    // --- Tes untuk registerMahasiswa ---
    @Test
    void testRegisterMahasiswa_Success() {
        // Arrange
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(userRepository.existsByNim(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("hashedPassword123");
        when(userRepository.save(any(User.class))).thenReturn(user); // save mengembalikan user yang disimpan

        // Act
        String result = authService.registerMahasiswa(registerRequest);

        // Assert
        assertEquals("Pendaftaran Akun Sukses!", result);
        verify(userRepository, times(1)).existsByEmail("test@example.com");
        verify(userRepository, times(1)).existsByNim("1234567890");
        verify(passwordEncoder, times(1)).encode("password123");
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void testRegisterMahasiswa_EmailAlreadyExists() {
        // Arrange
        when(userRepository.existsByEmail(anyString())).thenReturn(true);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerMahasiswa(registerRequest);
        });
        assertEquals("Error: Email sudah terdaftar!", exception.getMessage());
        verify(userRepository, times(1)).existsByEmail("test@example.com");
        verify(userRepository, never()).existsByNim(anyString());
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void testRegisterMahasiswa_NimAlreadyExists() {
        // Arrange
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(userRepository.existsByNim(anyString())).thenReturn(true);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerMahasiswa(registerRequest);
        });
        assertEquals("Error: NIM sudah terdaftar!", exception.getMessage());
        verify(userRepository, times(1)).existsByEmail("test@example.com");
        verify(userRepository, times(1)).existsByNim("1234567890");
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void testRegisterMahasiswa_PasswordMismatch() {
        // Arrange
        registerRequest.setConfirmPassword("wrongPassword");
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(userRepository.existsByNim(anyString())).thenReturn(false);
        // Tidak perlu mock passwordEncoder atau save karena akan gagal sebelumnya

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerMahasiswa(registerRequest);
        });
        assertEquals("Error: Password dan konfirmasi password tidak cocok!", exception.getMessage());
        verify(userRepository, times(1)).existsByEmail("test@example.com");
        verify(userRepository, times(1)).existsByNim("1234567890");
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void testRegisterMahasiswa_PasswordTooShort() {
        // Arrange
        registerRequest.setPassword("short"); // Password kurang dari 8 karakter
        registerRequest.setConfirmPassword("short");
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(userRepository.existsByNim(anyString())).thenReturn(false);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerMahasiswa(registerRequest);
        });
        assertEquals("Error: Password minimal 8 karakter!", exception.getMessage());
        verify(userRepository, times(1)).existsByEmail("test@example.com");
        verify(userRepository, times(1)).existsByNim("1234567890");
        verify(passwordEncoder, never()).encode(anyString()); // Tidak sampai encoding jika password tidak cocok
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void testRegisterMahasiswa_NimIsNull() {
        // Arrange
        registerRequest.setNim(null);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        // Tidak perlu mock existsByNim karena akan gagal karena NIM null

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerMahasiswa(registerRequest);
        });
        assertEquals("Error: NIM tidak boleh kosong untuk mahasiswa!", exception.getMessage());
        verify(userRepository, times(1)).existsByEmail("test@example.com");
        verify(userRepository, never()).existsByNim(anyString());
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }


    // --- Tes untuk login ---
    @Test
    void testLogin_Success() {
        // Arrange
        // Saat authenticationManager.authenticate dipanggil dengan kredensial yang benar,
        // ia akan mengembalikan objek Authentication yang sudah terautentikasi.
        when(authenticationManager.authenticate(
                any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication); // Mengembalikan mock Authentication

        // Mock Principal dari objek Authentication
        when(authentication.getPrincipal()).thenReturn(user);

        // Jika JwtTokenProvider sudah ada dan di-mock:
        // when(jwtTokenProvider.generateToken(any(Authentication.class))).thenReturn("generated-jwt-token");
        // atau
        // when(jwtTokenProvider.generateTokenFromUser(any(User.class))).thenReturn("generated-jwt-token");

        // Act
        AuthResponse authResponse = authService.login(loginRequest);

        // Assert
        assertNotNull(authResponse);
        // assertEquals("generated-jwt-token", authResponse.getToken()); // Jika JwtTokenProvider sudah di-mock
        assertEquals("dummy-jwt-token-akan-diganti-nanti", authResponse.getToken()); // Sesuai placeholder saat ini
        assertEquals(user.getId(), authResponse.getUserId());
        assertEquals(user.getEmail(), authResponse.getEmail());
        assertEquals(user.getNamaLengkap(), authResponse.getNamaLengkap());
        assertEquals(user.getRole().name(), authResponse.getRole());

        // Verifikasi bahwa SecurityContextHolder di-set
        assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());

        verify(authenticationManager, times(1)).authenticate(
                new UsernamePasswordAuthenticationToken("test@example.com", "password123")
        );
        // verify(jwtTokenProvider, times(1)).generateToken(authentication); // Jika sudah di-mock
    }

    @Test
    void testLogin_AuthenticationFailure() {
        // Arrange
        // Saat authenticationManager.authenticate dipanggil dengan kredensial salah,
        // ia akan melempar AuthenticationException (misalnya, BadCredentialsException).
        when(authenticationManager.authenticate(
                any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new org.springframework.security.authentication.BadCredentialsException("Bad credentials"));

        // Act & Assert
        assertThrows(org.springframework.security.authentication.BadCredentialsException.class, () -> {
            authService.login(loginRequest);
        });

        // Pastikan SecurityContextHolder tidak di-set
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(authenticationManager, times(1)).authenticate(
                new UsernamePasswordAuthenticationToken("test@example.com", "password123")
        );
        // verify(jwtTokenProvider, never()).generateToken(any(Authentication.class)); // Jika sudah di-mock
    }
}