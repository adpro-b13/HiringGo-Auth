package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.Role;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtAuthenticationFilter;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.service.UserDetailsServiceImpl;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.mockito.Mockito.never;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;


@ExtendWith(MockitoExtension.class)
class JwtAuthenticationStrategyTest {

    @Mock
    private JwtTokenProvider tokenProvider;

    @Mock
    private UserDetailsServiceImpl userDetailsService;

    @Mock
    private AuthenticationManager authenticationManager;

    @InjectMocks
    private JwtAuthenticationStrategy jwtAuthenticationStrategy;

    private LoginRequest loginRequest;
    private User userDetails;
    // private Authentication successfulAuthentication; // No longer a field, will be local

    @BeforeEach
    void setUp() {
        loginRequest = LoginRequest.builder()
                .email("testuser@example.com")
                .password("password123")
                .build();

        userDetails = User.builder()
                .id(1L)
                .email("testuser@example.com")
                .namaLengkap("Test User")
                .role(Role.MAHASISWA)
                .build();

        // REMOVE: successfulAuthentication = mock(Authentication.class);
        // REMOVE: when(successfulAuthentication.getPrincipal()).thenReturn(userDetails);
    }

    @Test
    void testCreateFilter_ReturnsJwtAuthenticationFilter() {
        // Act
        Filter filter = jwtAuthenticationStrategy.createFilter();

        // Assert
        assertNotNull(filter);
        assertTrue(filter instanceof JwtAuthenticationFilter);
    }

    @Test
    void testLogin_Success() {
        // Arrange
        // Create and configure successfulAuthentication mock locally
        Authentication successfulAuthentication = mock(Authentication.class);
        when(successfulAuthentication.getPrincipal()).thenReturn(userDetails);

        String fakeJwtToken = "fake.jwt.token";
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                loginRequest.getEmail(), loginRequest.getPassword());

        when(authenticationManager.authenticate(authToken)).thenReturn(successfulAuthentication);
        when(tokenProvider.generateToken(successfulAuthentication)).thenReturn(fakeJwtToken);

        // Act
        AuthResponse authResponse = jwtAuthenticationStrategy.login(loginRequest);

        // Assert
        assertNotNull(authResponse);
        assertEquals(fakeJwtToken, authResponse.getToken());
        assertEquals(userDetails.getId(), authResponse.getUserId());
        assertEquals(userDetails.getEmail(), authResponse.getEmail());
        assertEquals(userDetails.getNamaLengkap(), authResponse.getNamaLengkap());
        assertEquals(userDetails.getRole().name(), authResponse.getRole());

        verify(authenticationManager).authenticate(authToken);
        verify(tokenProvider).generateToken(successfulAuthentication);
        verify(successfulAuthentication).getPrincipal(); // Verify interaction
    }

    @Test
    void testLogin_AuthenticationFailure() {
        // Arrange
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                loginRequest.getEmail(), loginRequest.getPassword());
        when(authenticationManager.authenticate(authToken))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // Act & Assert
        assertThrows(BadCredentialsException.class, () -> {
            jwtAuthenticationStrategy.login(loginRequest);
        });

        verify(authenticationManager).authenticate(authToken);
        verify(tokenProvider, never()).generateToken(any(Authentication.class));
    }
}