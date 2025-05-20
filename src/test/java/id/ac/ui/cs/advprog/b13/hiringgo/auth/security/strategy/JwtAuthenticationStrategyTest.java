package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtAuthenticationFilter;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.service.UserDetailsServiceImpl;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationStrategyTest {

    @Mock
    private JwtTokenProvider tokenProvider;

    @Mock
    private UserDetailsServiceImpl userDetailsService;

    private JwtAuthenticationStrategy jwtAuthenticationStrategy;

    @BeforeEach
    void setUp() {
        jwtAuthenticationStrategy = new JwtAuthenticationStrategy(tokenProvider, userDetailsService);
    }

    @Test
    void testCreateFilter_ReturnsJwtAuthenticationFilter() {
        // Act
        Filter filter = jwtAuthenticationStrategy.createFilter();

        // Assert
        assertNotNull(filter);
        assertTrue(filter instanceof JwtAuthenticationFilter);
    }
}