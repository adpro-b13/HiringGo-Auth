package id.ac.ui.cs.advprog.b13.hiringgo.auth.service;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.RegisterRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.Role;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.repository.UserRepository;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.factory.AuthenticationStrategyFactory; // Added
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy.AuthenticationStrategy; // Added
// import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider; // No longer directly used here for login
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
// import org.springframework.security.authentication.AuthenticationManager; // No longer directly used here for login
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {
    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;

    // Remove @Mock private AuthenticationManager authenticationManager;
    // Remove @Mock private JwtTokenProvider jwtTokenProvider; // Not directly used in AuthServiceImpl's login anymore

    @Mock
    private AuthenticationStrategyFactory jwtAuthFactory; // Mock the factory

    @Mock
    private AuthenticationStrategy authenticationStrategy; // Mock the strategy product

    @InjectMocks
    private AuthServiceImpl authService;

    private RegisterRequest registerRequestMahasiswa;
    private RegisterRequest registerRequestDosen;
    private LoginRequest loginRequestMahasiswa;
    private User userMahasiswaEntity;
    // private User userDosenEntity; // Not used in current login tests
    // private Authentication authentication; // Mocked Authentication object, not directly set in context by service anymore

    @BeforeEach
    void setUp() {
        registerRequestMahasiswa = RegisterRequest.builder()
                .namaLengkap("Test Mahasiswa")
                .email("mahasiswa.test@example.com")
                .password("password123")
                .confirmPassword("password123")
                .role(Role.MAHASISWA)
                .nim("1234567890")
                .build();

        userMahasiswaEntity = User.builder()
                .id(1L)
                .namaLengkap("Test Mahasiswa")
                .email("mahasiswa.test@example.com")
                .password("hashedPasswordMhs") // Password in entity would be hashed
                .role(Role.MAHASISWA)
                .nim("1234567890")
                .build();

        registerRequestDosen = RegisterRequest.builder()
                .namaLengkap("Test Dosen")
                .email("dosen.test@example.com")
                .password("passwordDosenKuat")
                .confirmPassword("passwordDosenKuat")
                .role(Role.DOSEN)
                .nip("0987654321")
                .build();

        // userDosenEntity not strictly needed for current tests, but good to have if expanding
        // userDosenEntity = User.builder()
        //         .id(2L)
        //         .namaLengkap("Test Dosen")
        //         .email("dosen.test@example.com")
        //         .password("hashedPasswordDosen")
        //         .role(Role.DOSEN)
        //         .nip("0987654321")
        //         .build();

        loginRequestMahasiswa = LoginRequest.builder()
                .email("mahasiswa.test@example.com")
                .password("password123")
                .build();

        // authentication = mock(Authentication.class); // Not directly used by AuthServiceImpl for setting context

        // Mock the factory to return our mock strategy
//        when(jwtAuthFactory.createStrategy()).thenReturn(authenticationStrategy);

        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // --- REGISTER Tests remain the same ---
    @Test
    void testRegisterUser_Mahasiswa_Success() {
        when(userRepository.existsByEmail(registerRequestMahasiswa.getEmail())).thenReturn(false);
        when(userRepository.existsByNim(registerRequestMahasiswa.getNim())).thenReturn(false);
        when(passwordEncoder.encode(registerRequestMahasiswa.getPassword())).thenReturn("hashedPasswordMhs");
        when(userRepository.save(any(User.class))).thenReturn(userMahasiswaEntity); // Ensure this returns a User object

        String result = authService.registerUser(registerRequestMahasiswa);
        assertEquals("Pendaftaran Akun MAHASISWA Sukses!", result);

        verify(userRepository).existsByEmail(registerRequestMahasiswa.getEmail());
        verify(userRepository).existsByNim(registerRequestMahasiswa.getNim());
        verify(passwordEncoder).encode(registerRequestMahasiswa.getPassword());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void testRegisterUser_Dosen_RegistrationNotAllowed_EvenIfNipIsNull() {
        registerRequestDosen.setNip(null);
        when(userRepository.existsByEmail(registerRequestDosen.getEmail())).thenReturn(false);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestDosen);
        });
        assertEquals("Error: Registrasi sebagai DOSEN tidak diizinkan melalui endpoint ini.", exception.getMessage());

        verify(userRepository).existsByEmail(registerRequestDosen.getEmail());
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void testRegisterUser_EmailAlreadyExists() {
        when(userRepository.existsByEmail(registerRequestMahasiswa.getEmail())).thenReturn(true);
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestMahasiswa);
        });
        assertEquals("Error: Email sudah terdaftar!", exception.getMessage());
        verify(userRepository).existsByEmail(registerRequestMahasiswa.getEmail());
        verifyNoMoreInteractions(passwordEncoder); // userRepository might be interacted with again if existsByEmail is called multiple times.
        // If only called once, then verifyNoMoreInteractions(passwordEncoder, userRepository) is fine.
        verify(userRepository, never()).save(any(User.class)); // More specific
    }


    @Test
    void testRegisterUser_Mahasiswa_NimAlreadyExists() {
        when(userRepository.existsByEmail(registerRequestMahasiswa.getEmail())).thenReturn(false);
        when(userRepository.existsByNim(registerRequestMahasiswa.getNim())).thenReturn(true);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestMahasiswa);
        });

        assertEquals("Error: NIM sudah terdaftar!", exception.getMessage());
        verify(userRepository).existsByEmail(registerRequestMahasiswa.getEmail());
        verify(userRepository).existsByNim(registerRequestMahasiswa.getNim());
        verifyNoMoreInteractions(passwordEncoder);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void testRegisterUser_Mahasiswa_NimIsNull() {
        registerRequestMahasiswa.setNim(null);
        when(userRepository.existsByEmail(registerRequestMahasiswa.getEmail())).thenReturn(false);
        // No need to mock existsByNim as the null check for NIM comes first for MAHASISWA.

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestMahasiswa);
        });

        assertEquals("Error: NIM tidak boleh kosong untuk mahasiswa!", exception.getMessage());
        verify(userRepository).existsByEmail(registerRequestMahasiswa.getEmail());
        verifyNoMoreInteractions(passwordEncoder);
        verify(userRepository, never()).existsByNim(anyString()); // Make sure this wasn't called
        verify(userRepository, never()).save(any(User.class));
    }


    @Test
    void testRegisterUser_Dosen_RegistrationNotAllowed() {
        when(userRepository.existsByEmail(registerRequestDosen.getEmail())).thenReturn(false);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestDosen);
        });
        assertEquals("Error: Registrasi sebagai DOSEN tidak diizinkan melalui endpoint ini.", exception.getMessage());
        verify(userRepository).existsByEmail(registerRequestDosen.getEmail());
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void testRegisterUser_PasswordMismatch() {
        registerRequestMahasiswa.setConfirmPassword("wrongPassword");
        // No need to mock userRepository.existsByEmail if it's not reached,
        // but it's fine to mock it to pass the first check if the order is fixed.
        when(userRepository.existsByEmail(anyString())).thenReturn(false);


        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestMahasiswa);
        });
        assertEquals("Error: Password dan konfirmasi password tidak cocok!", exception.getMessage());
        verify(userRepository).existsByEmail(registerRequestMahasiswa.getEmail());
        verifyNoMoreInteractions(passwordEncoder);
        verify(userRepository, never()).save(any(User.class)); // More specific
    }

    @Test
    void testRegisterUser_PasswordTooShort() {
        registerRequestMahasiswa.setPassword("short");
        registerRequestMahasiswa.setConfirmPassword("short");
        when(userRepository.existsByEmail(anyString())).thenReturn(false);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestMahasiswa);
        });
        assertEquals("Error: Password minimal 8 karakter!", exception.getMessage());
        verify(userRepository).existsByEmail(registerRequestMahasiswa.getEmail());
        verifyNoMoreInteractions(passwordEncoder);
        verify(userRepository, never()).save(any(User.class)); // More specific
    }

    @Test
    void testRegisterUser_AdminRole_ThrowsException() {
        RegisterRequest adminRequest = RegisterRequest.builder()
                .namaLengkap("Test Admin")
                .email("admin.test@example.com")
                .password("passwordAdmin")
                .confirmPassword("passwordAdmin")
                .role(Role.ADMIN)
                .build();
        when(userRepository.existsByEmail(adminRequest.getEmail())).thenReturn(false);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(adminRequest);
        });
        assertEquals("Error: Registrasi sebagai ADMIN tidak diizinkan melalui endpoint ini.", exception.getMessage());
        verify(userRepository).existsByEmail(adminRequest.getEmail());
        verifyNoMoreInteractions(passwordEncoder);
        verify(userRepository, never()).save(any(User.class)); // More specific
    }

    // --- LOGIN ---
    @Test
    void testLogin_Success_DelegatesToStrategy() {
        // Arrange
        // ADD STUBBING HERE
        when(jwtAuthFactory.createStrategy()).thenReturn(authenticationStrategy);

        AuthResponse expectedAuthResponse = AuthResponse.builder()
                .token("token-jwt-fake-mahasiswa")
                .userId(userMahasiswaEntity.getId())
                .email(userMahasiswaEntity.getEmail())
                .namaLengkap(userMahasiswaEntity.getNamaLengkap())
                .role(userMahasiswaEntity.getRole().name())
                .build();

        when(authenticationStrategy.login(loginRequestMahasiswa)).thenReturn(expectedAuthResponse);

        // Act
        AuthResponse actualAuthResponse = authService.login(loginRequestMahasiswa);

        // Assert
        assertNotNull(actualAuthResponse);
        assertEquals(expectedAuthResponse.getToken(), actualAuthResponse.getToken());
        // ... other assertions ...

        verify(jwtAuthFactory).createStrategy();
        verify(authenticationStrategy).login(loginRequestMahasiswa);
    }

    @Test
    void testLogin_AuthenticationFailure_DelegatesToStrategyAndPropagatesException() {
        // Arrange
        // ADD STUBBING HERE
        when(jwtAuthFactory.createStrategy()).thenReturn(authenticationStrategy);

        org.springframework.security.authentication.BadCredentialsException expectedException =
                new org.springframework.security.authentication.BadCredentialsException("Bad credentials from strategy");
        when(authenticationStrategy.login(loginRequestMahasiswa)).thenThrow(expectedException);

        // Act & Assert
        org.springframework.security.authentication.BadCredentialsException actualException =
                assertThrows(org.springframework.security.authentication.BadCredentialsException.class, () -> {
                    authService.login(loginRequestMahasiswa);
                });

        assertEquals(expectedException.getMessage(), actualException.getMessage());

        verify(jwtAuthFactory).createStrategy();
        verify(authenticationStrategy).login(loginRequestMahasiswa);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
}