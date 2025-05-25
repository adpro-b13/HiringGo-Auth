package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.factory;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy.AuthenticationStrategy;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy.JwtAuthenticationStrategy;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.service.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.beans.factory.ObjectProvider;

@Component("jwtStrategyFactory")
@RequiredArgsConstructor
public class JwtStrategyFactory implements AuthenticationStrategyFactory {

    private final JwtTokenProvider tokenProvider;
    private final UserDetailsServiceImpl userDetailsService;
    private final ObjectProvider<AuthenticationManager> authenticationManagerProvider;

    @Override
    public AuthenticationStrategy createStrategy() {
        return new JwtAuthenticationStrategy(
                tokenProvider,
                userDetailsService,
                authenticationManagerProvider.getObject()
        );
    }
}
