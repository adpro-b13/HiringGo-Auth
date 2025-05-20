package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.factory;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy.AuthenticationStrategy;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy.JwtAuthenticationStrategy;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.service.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component("jwtStrategyFactory") // Beri nama bean jika ada beberapa factory
@RequiredArgsConstructor
public class JwtStrategyFactory implements AuthenticationStrategyFactory {

    private final JwtTokenProvider tokenProvider;
    private final UserDetailsServiceImpl userDetailsService; // atau UserDetailsService

    @Override
    public AuthenticationStrategy createStrategy() {
        return new JwtAuthenticationStrategy(tokenProvider, userDetailsService);
    }
}