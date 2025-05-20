package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.factory;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy.AuthenticationStrategy;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy.JwtAuthenticationStrategy;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.service.UserDetailsServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class JwtStrategyFactoryTest {

    @Mock
    private JwtTokenProvider tokenProvider;

    @Mock
    private UserDetailsServiceImpl userDetailsService;

    @InjectMocks
    private JwtStrategyFactory jwtStrategyFactory;

    @Test
    void testCreateStrategy_ReturnsJwtAuthenticationStrategy() {
        // Act
        AuthenticationStrategy strategy = jwtStrategyFactory.createStrategy();

        // Assert
        assertNotNull(strategy);
        assertTrue(strategy instanceof JwtAuthenticationStrategy);
    }
}