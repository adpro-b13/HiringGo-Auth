package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.factory;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy.AuthenticationStrategy;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy.JwtAuthenticationStrategy;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.service.UserDetailsServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider; // Import ObjectProvider
import org.springframework.security.authentication.AuthenticationManager;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify; // Import verify
import static org.mockito.Mockito.when; // Import when

@ExtendWith(MockitoExtension.class)
class JwtStrategyFactoryTest {

    @Mock
    private JwtTokenProvider tokenProvider;

    @Mock
    private UserDetailsServiceImpl userDetailsService;

    @Mock
    private ObjectProvider<AuthenticationManager> authenticationManagerProvider; // Mock the ObjectProvider

    @Mock
    private AuthenticationManager authenticationManager; // This will be returned by the provider

    @InjectMocks
    private JwtStrategyFactory jwtStrategyFactory;

    @Test
    void testCreateStrategy_ReturnsJwtAuthenticationStrategy() {
        // Arrange: Configure the mock ObjectProvider to return the mock AuthenticationManager
        when(authenticationManagerProvider.getObject()).thenReturn(authenticationManager);

        // Act
        AuthenticationStrategy strategy = jwtStrategyFactory.createStrategy();

        // Assert
        assertNotNull(strategy);
        assertTrue(strategy instanceof JwtAuthenticationStrategy);
        // Verify that getObject() was called on the provider, ensuring correct wiring
        verify(authenticationManagerProvider).getObject();
    }
}