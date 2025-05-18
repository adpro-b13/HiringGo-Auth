package id.ac.ui.cs.advprog.b13.hiringgo.auth.service;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.RegisterRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.Role;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.repository.UserRepository;
// import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider;

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

    // @Mock
    // private JwtTokenProvider jwtTokenProvider;

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
        // Setup untuk registrasi Mahasiswa
        registerRequestMahasiswa = RegisterRequest.builder()
                .namaLengkap("Test Mahasiswa")
                .email("mahasiswa.test@example.com")
                .password("password123")
                .confirmPassword("password123")
                .role(Role.MAHASISWA) // Penting: set role
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

        // Setup untuk registrasi Dosen
        registerRequestDosen = RegisterRequest.builder()
                .namaLengkap("Test Dosen")
                .email("dosen.test@example.com")
                .password("passwordDosenKuat")
                .confirmPassword("passwordDosenKuat")
                .role(Role.DOSEN) // Penting: set role
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

        // Setup untuk login (bisa menggunakan salah satu user)
        loginRequestMahasiswa = LoginRequest.builder()
                .email("mahasiswa.test@example.com")
                .password("password123")
                .build();

        authentication = mock(Authentication.class);
        SecurityContextHolder.clearContext();
    }

    // --- Tes untuk registerUser ---

    @Test
    void testRegisterUser_Mahasiswa_Success() {
        when(userRepository.existsByEmail(registerRequestMahasiswa.getEmail())).thenReturn(false);
        when(userRepository.existsByNim(registerRequestMahasiswa.getNim())).thenReturn(false);
        when(passwordEncoder.encode(registerRequestMahasiswa.getPassword())).thenReturn("hashedPasswordMhs");
        when(userRepository.save(any(User.class))).thenReturn(userMahasiswaEntity);

        String result = authService.registerUser(registerRequestMahasiswa);

        assertEquals("Pendaftaran Akun MAHASISWA Sukses!", result);
        verify(userRepository, times(1)).existsByEmail(registerRequestMahasiswa.getEmail());
        verify(userRepository, times(1)).existsByNim(registerRequestMahasiswa.getNim());
        verify(passwordEncoder, times(1)).encode(registerRequestMahasiswa.getPassword());
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void testRegisterUser_Dosen_Success() {
        when(userRepository.existsByEmail(registerRequestDosen.getEmail())).thenReturn(false);
        // Asumsi tidak ada existsByNip di service, atau jika ada, mock juga
        // when(userRepository.existsByNip(registerRequestDosen.getNip())).thenReturn(false);
        when(passwordEncoder.encode(registerRequestDosen.getPassword())).thenReturn("hashedPasswordDosen");
        when(userRepository.save(any(User.class))).thenReturn(userDosenEntity);

        String result = authService.registerUser(registerRequestDosen);

        assertEquals("Pendaftaran Akun DOSEN Sukses!", result);
        verify(userRepository, times(1)).existsByEmail(registerRequestDosen.getEmail());
        // verify(userRepository, times(1)).existsByNip(registerRequestDosen.getNip()); // Jika ada
        verify(passwordEncoder, times(1)).encode(registerRequestDosen.getPassword());
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void testRegisterUser_EmailAlreadyExists() {
        when(userRepository.existsByEmail(registerRequestMahasiswa.getEmail())).thenReturn(true);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestMahasiswa);
        });
        assertEquals("Error: Email sudah terdaftar!", exception.getMessage());
        verify(userRepository, times(1)).existsByEmail(registerRequestMahasiswa.getEmail());
        verifyNoMoreInteractions(passwordEncoder, userRepository); // Pastikan tidak ada interaksi lain
    }

    @Test
    void testRegisterUser_Mahasiswa_NimAlreadyExists() {
        registerRequestMahasiswa.setRole(Role.MAHASISWA); // Pastikan role adalah Mahasiswa
        when(userRepository.existsByEmail(registerRequestMahasiswa.getEmail())).thenReturn(false);
        when(userRepository.existsByNim(registerRequestMahasiswa.getNim())).thenReturn(true);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestMahasiswa);
        });
        assertEquals("Error: NIM sudah terdaftar!", exception.getMessage());
        verify(userRepository, times(1)).existsByEmail(registerRequestMahasiswa.getEmail());
        verify(userRepository, times(1)).existsByNim(registerRequestMahasiswa.getNim());
        verifyNoMoreInteractions(passwordEncoder);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void testRegisterUser_Mahasiswa_NimIsNull() {
        registerRequestMahasiswa.setNim(null); // Set NIM jadi null untuk tes ini
        registerRequestMahasiswa.setRole(Role.MAHASISWA);
        when(userRepository.existsByEmail(registerRequestMahasiswa.getEmail())).thenReturn(false);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestMahasiswa);
        });
        assertEquals("Error: NIM tidak boleh kosong untuk mahasiswa!", exception.getMessage());
        verify(userRepository, times(1)).existsByEmail(registerRequestMahasiswa.getEmail());
        verifyNoMoreInteractions(passwordEncoder, userRepository);
    }

    @Test
    void testRegisterUser_Dosen_NipIsNull() {
        registerRequestDosen.setNip(null); // Set NIP jadi null untuk tes ini
        registerRequestDosen.setRole(Role.DOSEN);
        when(userRepository.existsByEmail(registerRequestDosen.getEmail())).thenReturn(false);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestDosen);
        });
        assertEquals("Error: NIP tidak boleh kosong untuk dosen!", exception.getMessage());
        verify(userRepository, times(1)).existsByEmail(registerRequestDosen.getEmail());
        verifyNoMoreInteractions(passwordEncoder, userRepository);
    }

    @Test
    void testRegisterUser_PasswordMismatch() {
        registerRequestMahasiswa.setConfirmPassword("wrongPassword");
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        // Tidak perlu mock existsByNim/Nip karena akan gagal di password

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(registerRequestMahasiswa);
        });
        assertEquals("Error: Password dan konfirmasi password tidak cocok!", exception.getMessage());
        verify(userRepository, times(1)).existsByEmail(registerRequestMahasiswa.getEmail());
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
        verify(userRepository, times(1)).existsByEmail(registerRequestMahasiswa.getEmail());
        verifyNoMoreInteractions(passwordEncoder, userRepository);
    }

    @Test
    void testRegisterUser_AdminRole_ThrowsException() {
        RegisterRequest adminRequest = RegisterRequest.builder()
                .namaLengkap("Test Admin")
                .email("admin.test@example.com")
                .password("passwordAdmin")
                .confirmPassword("passwordAdmin")
                .role(Role.ADMIN) // Mencoba mendaftar sebagai ADMIN
                .build();

        when(userRepository.existsByEmail(adminRequest.getEmail())).thenReturn(false);
        // Tidak perlu mock passwordEncoder atau save karena akan gagal sebelumnya

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.registerUser(adminRequest);
        });
        assertEquals("Error: Registrasi sebagai ADMIN tidak diizinkan melalui endpoint ini.", exception.getMessage());
        verify(userRepository, times(1)).existsByEmail(adminRequest.getEmail());
        verifyNoMoreInteractions(passwordEncoder, userRepository);
    }


    // --- Tes untuk login ---
    @Test
    void testLogin_Success_ForMahasiswa() {
        when(authenticationManager.authenticate(
                any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userMahasiswaEntity);
        // when(jwtTokenProvider.generateTokenFromUser(userMahasiswaEntity)).thenReturn("jwt-token-mahasiswa");

        AuthResponse authResponse = authService.login(loginRequestMahasiswa);

        assertNotNull(authResponse);
        assertEquals("dummy-jwt-token-akan-diganti-nanti", authResponse.getToken());
        assertEquals(userMahasiswaEntity.getId(), authResponse.getUserId());
        assertEquals(userMahasiswaEntity.getEmail(), authResponse.getEmail());
        assertEquals(userMahasiswaEntity.getNamaLengkap(), authResponse.getNamaLengkap());
        assertEquals(userMahasiswaEntity.getRole().name(), authResponse.getRole());
        assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
        verify(authenticationManager, times(1)).authenticate(
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
        verify(authenticationManager, times(1)).authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestMahasiswa.getEmail(), loginRequestMahasiswa.getPassword())
        );
    }
}