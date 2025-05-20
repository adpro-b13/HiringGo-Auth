package id.ac.ui.cs.advprog.b13.hiringgo.auth.controller;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.config.GlobalExceptionHandler;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.config.SecurityConfig;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.RegisterRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.Role;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.core.userdetails.UserDetailsService;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.factory.AuthenticationStrategyFactory;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy.AuthenticationStrategy;
import jakarta.servlet.Filter;

import org.mockito.ArgumentCaptor;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import static org.mockito.Mockito.mock;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf; // <--- IMPORT INI
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.is;

@WebMvcTest(AuthController.class)
@Import({SecurityConfig.class, GlobalExceptionHandler.class, AuthControllerTest.TestSecurityConfiguration.class}) // Tambahkan TestSecurityConfiguration
class AuthControllerTest {

    // Definisikan konfigurasi tes statis di dalam kelas tes
    @TestConfiguration
    static class TestSecurityConfiguration {
        @Bean
        @Primary
        public AuthenticationStrategyFactory jwtStrategyFactoryMock() {
            AuthenticationStrategyFactory factoryMock = mock(AuthenticationStrategyFactory.class);
            AuthenticationStrategy strategyMock = mock(AuthenticationStrategy.class);

            // --- Pakai dummy filter yang pasti call filterChain.doFilter (tidak block request) ---
            jakarta.servlet.Filter dummyFilter = (servletRequest, servletResponse, filterChain) -> {
                filterChain.doFilter(servletRequest, servletResponse);
            };

            when(strategyMock.createFilter()).thenReturn(dummyFilter);
            when(factoryMock.createStrategy()).thenReturn(strategyMock);
            return factoryMock;
        }
    }


    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserDetailsService userDetailsService;

    @MockBean
    private AuthService authService;

    @Autowired
    private ObjectMapper objectMapper;

    private RegisterRequest registerRequestMahasiswa;
    private RegisterRequest registerRequestDosen;
    private LoginRequest loginRequest;
    private AuthResponse authResponse;

    @BeforeEach
    void setUp() {
        registerRequestMahasiswa = RegisterRequest.builder()
                // ... (definisi)
                .namaLengkap("Test Mahasiswa")
                .email("mahasiswa.test@example.com")
                .password("password123")
                .confirmPassword("password123")
                .role(Role.MAHASISWA)
                .nim("1234567890")
                .build();

        registerRequestDosen = RegisterRequest.builder()
                // ... (definisi)
                .namaLengkap("Test Dosen")
                .email("dosen.test@example.com")
                .password("passwordDosenKuat")
                .confirmPassword("passwordDosenKuat")
                .role(Role.DOSEN)
                .nip("0987654321")
                .build();

        loginRequest = LoginRequest.builder()
                .email("mahasiswa.test@example.com")
                .password("password123")
                .build();

        authResponse = AuthResponse.builder()
                .token("dummy-jwt-token")
                .userId(1L)
                .email("mahasiswa.test@example.com")
                .namaLengkap("Test Mahasiswa")
                .role("MAHASISWA")
                .build();
    }

    @Test
    void testRegisterUser_Mahasiswa_Success() throws Exception {
        String expectedMessage = "Pendaftaran Akun MAHASISWA Sukses!";
        // Pastikan mock dikonfigurasi untuk RegisterRequest apa pun
        when(authService.registerUser(any(RegisterRequest.class)))
                .thenReturn(expectedMessage);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequestMahasiswa))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string(expectedMessage)); // Bandingkan dengan string yang sama

        verify(authService).registerUser(any(RegisterRequest.class));
    }

    @Test
    void testRegisterUser_Dosen_Success() throws Exception {
        when(authService.registerUser(any(RegisterRequest.class)))
                .thenReturn("Pendaftaran Akun DOSEN Sukses!");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequestDosen))
                        .with(csrf())) // <--- TAMBAHKAN .with(csrf())
                .andExpect(status().isOk())
                .andExpect(content().string("Pendaftaran Akun DOSEN Sukses!"));
        verify(authService).registerUser(any(RegisterRequest.class));
    }

    @Test
    void testRegisterUser_IllegalArgumentException() throws Exception {
        String errorMessage = "Error: Email sudah terdaftar!";
        when(authService.registerUser(any(RegisterRequest.class)))
                .thenThrow(new IllegalArgumentException(errorMessage));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequestMahasiswa))
                        .with(csrf())) // <--- TAMBAHKAN .with(csrf())
                .andExpect(status().isBadRequest())
                .andExpect(content().string(errorMessage));
        verify(authService).registerUser(any(RegisterRequest.class));
    }

    @Test
    void testRegisterUser_GenericException() throws Exception {
        when(authService.registerUser(any(RegisterRequest.class)))
                .thenThrow(new RuntimeException("Some unexpected error"));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequestMahasiswa))
                        .with(csrf())) // <--- TAMBAHKAN .with(csrf())
                .andExpect(status().isInternalServerError())
                .andExpect(content().string("Terjadi kesalahan internal saat registrasi."));
        verify(authService).registerUser(any(RegisterRequest.class));
    }

    @Test
    void testLoginUser_Success() throws Exception {
        when(authService.login(any(LoginRequest.class)))
                .thenReturn(authResponse);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest))
                        .with(csrf())) // <--- TAMBAHKAN .with(csrf())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token", is(authResponse.getToken())))
                .andExpect(jsonPath("$.email", is(authResponse.getEmail())))
                .andExpect(jsonPath("$.role", is(authResponse.getRole())));
        verify(authService).login(any(LoginRequest.class));
    }

    @Test
    void testLoginUser_AuthenticationFailure() throws Exception {
        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new AuthenticationException("Kredensial buruk simulasi") {});

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest))
                        .with(csrf())) // <--- TAMBAHKAN .with(csrf())
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Login gagal: Kredensial tidak valid."));
        verify(authService).login(any(LoginRequest.class));
    }

    @Test
    void testLoginUser_GenericException() throws Exception {
        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new RuntimeException("Some unexpected error"));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest))
                        .with(csrf())) // <--- TAMBAHKAN .with(csrf())
                .andExpect(status().isInternalServerError())
                .andExpect(content().string("Terjadi kesalahan internal saat login."));
        verify(authService).login(any(LoginRequest.class));
    }

    @Test
    void testRegisterUser_InvalidInput_BlankEmail() throws Exception {
        RegisterRequest invalidRequest = RegisterRequest.builder()
                .namaLengkap("Test User")
                .email("") // Email kosong
                .password("password123")
                .confirmPassword("password123")
                .role(Role.MAHASISWA)
                .nim("1234567890")
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest))
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                // Pastikan jsonPath() ini sesuai dengan struktur JSON yang dihasilkan oleh GlobalExceptionHandler-mu
                .andExpect(jsonPath("$.errors.email", is("Email tidak boleh kosong")));
    }
}