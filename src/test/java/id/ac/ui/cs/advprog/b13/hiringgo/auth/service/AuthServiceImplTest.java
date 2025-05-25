package id.ac.ui.cs.advprog.b13.hiringgo.auth.service;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.RegisterRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.Role;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.repository.UserRepository;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider;

import org.junit.jupiter.api.AfterEach;
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

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @InjectMocks
    private AuthServiceImpl authService;

    private RegisterRequest registerRequestMahasiswa;
    private RegisterRequest registerRequestDosen;
    private LoginRequest loginRequestMahasiswa;

    private User userMahasiswaEntity;
    private User userDosenEntity;

    private Authentication authentication;

    @BeforeEach
    void setUp() {
        // -- RegisterRequest dan Entitas Mahasiswa
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
                .password("hashedPasswordMhs")
                .role(Role.MAHASISWA)
                .nim("1234567890")
                .build();

        // -- RegisterRequest dan Entitas Dosen
        registerRequestDosen = RegisterRequest.builder()
                .namaLengkap("Test Dosen")
                .email("dosen.test@example.com")
                .password("passwordDosenKuat")
                .confirmPassword("passwordDosenKuat")
                .role(Role.DOSEN)
                .nip("0987654321")
                .build();

        userDosenEntity = User.builder()
                .id(2L)
                .namaLengkap("Test Dosen")
                .email("dosen.test@example.com")
                .password("hashedPasswordDosen")
                .role(Role.DOSEN)
                .nip("0987654321")
                .build();

        loginRequestMahasiswa = LoginRequest.builder()
                .email("mahasiswa.test@example.com")
                .password("password123")
                .build();

        authentication = mock(Authentication.class);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // --- REGISTER ---

    @Test
    void testRegisterUser_Mahasiswa_Success() {
        when(userRepository.existsByEmail(registerRequestMahasiswa.getEmail())).thenReturn(false);
        when(userRepository.existsByNim(registerRequestMahasiswa.getNim())).thenReturn(false);
        when(passwordEncoder.encode(registerRequestMahasiswa.getPassword())).thenReturn("hashedPasswordMhs");
        when(userRepository.save(any(User.class))).thenReturn(userMahasiswaEntity);

        String result = authService.registerUser(registerRequestMahasiswa);

        assertEquals("Pendaftaran Akun MAHASISWA Sukses!", result);
        verify(userRepository).existsByEmail(registerRequestMahasiswa.getEmail());
        verify(userRepository).existsByNim(registerRequestMahasiswa.getNim());
        verify(passwordEncoder).encode(registerRequestMahasiswa.getPassword());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void testRegisterUser_Dosen_RegistrationNotAllowed_EvenIfNipIsNull() { // Renamed for clarity
        registerRequestDosen.setNip(null); // Keep this to show the original intent, though the specific NIP error won't be reached
        when(userRepository.existsByEmail(registerRequestDosen.getEmail())).thenReturn(false);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestDosen);
        });

        assertEquals("Error: Registrasi sebagai DOSEN tidak diizinkan melalui endpoint ini.", exception.getMessage());
        verify(userRepository).existsByEmail(registerRequestDosen.getEmail()); // This check might still run
        // Verify that password encoding, saving, and specific NIP checks (if any were previously mocked for this) are NOT called
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
        // If you had other mocks like existsByNip, verify they are not called:
        // verify(userRepository, never()).existsByNip(anyString());
    }

    @Test
    void testRegisterUser_EmailAlreadyExists() {
        when(userRepository.existsByEmail(registerRequestMahasiswa.getEmail())).thenReturn(true);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestMahasiswa);
        });
        assertEquals("Error: Email sudah terdaftar!", exception.getMessage());
        verify(userRepository).existsByEmail(registerRequestMahasiswa.getEmail());
        verifyNoMoreInteractions(passwordEncoder, userRepository);
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

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestMahasiswa);
        });
        assertEquals("Error: NIM tidak boleh kosong untuk mahasiswa!", exception.getMessage());
        verify(userRepository).existsByEmail(registerRequestMahasiswa.getEmail());
        verifyNoMoreInteractions(passwordEncoder, userRepository);
    }

    @Test
    void testRegisterUser_Dosen_RegistrationNotAllowed() { // Renamed for clarity
        // No need to mock passwordEncoder or userRepository.save as the method should fail earlier
        when(userRepository.existsByEmail(registerRequestDosen.getEmail())).thenReturn(false);
        // Any other initial checks that happen before role validation can be mocked if necessary

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestDosen);
        });

        assertEquals("Error: Registrasi sebagai DOSEN tidak diizinkan melalui endpoint ini.", exception.getMessage());
        verify(userRepository).existsByEmail(registerRequestDosen.getEmail()); // This check might still run
        // Verify that password encoding and saving are NOT called
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void testRegisterUser_PasswordMismatch() {
        registerRequestMahasiswa.setConfirmPassword("wrongPassword");
        when(userRepository.existsByEmail(anyString())).thenReturn(false);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestMahasiswa);
        });
        assertEquals("Error: Password dan konfirmasi password tidak cocok!", exception.getMessage());
        verify(userRepository).existsByEmail(registerRequestMahasiswa.getEmail());
        verifyNoMoreInteractions(passwordEncoder, userRepository);
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
        verifyNoMoreInteractions(passwordEncoder, userRepository);
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
        verifyNoMoreInteractions(passwordEncoder, userRepository);
    }

    // --- LOGIN ---

    @Test
    void testLogin_Success_ForMahasiswa() {
        when(authenticationManager.authenticate(
                any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userMahasiswaEntity);
        // Penting! Mock generateToken agar tidak NPE & hasil sesuai ekspektasi:
        when(jwtTokenProvider.generateToken(any(Authentication.class)))
                .thenReturn("token-jwt-fake-mahasiswa");

        AuthResponse authResponse = authService.login(loginRequestMahasiswa);

        assertNotNull(authResponse);
        assertEquals("token-jwt-fake-mahasiswa", authResponse.getToken());
        assertEquals(userMahasiswaEntity.getId(), authResponse.getUserId());
        assertEquals(userMahasiswaEntity.getEmail(), authResponse.getEmail());
        assertEquals(userMahasiswaEntity.getNamaLengkap(), authResponse.getNamaLengkap());
        assertEquals(userMahasiswaEntity.getRole().name(), authResponse.getRole());
        assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
        verify(authenticationManager).authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestMahasiswa.getEmail(), loginRequestMahasiswa.getPassword())
        );
    }

    @Test
    void testLogin_AuthenticationFailure() {
        when(authenticationManager.authenticate(
                any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new org.springframework.security.authentication.BadCredentialsException("Bad credentials"));

        assertThrows(org.springframework.security.authentication.BadCredentialsException.class, () -> {
            authService.login(loginRequestMahasiswa);
        });
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(authenticationManager).authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestMahasiswa.getEmail(), loginRequestMahasiswa.getPassword())
        );
    }
}