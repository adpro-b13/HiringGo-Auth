package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtAuthenticationFilter;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.service.UserDetailsServiceImpl;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

@RequiredArgsConstructor // Constructor akan di-handle oleh Factory
public class JwtAuthenticationStrategy implements AuthenticationStrategy {

    private final JwtTokenProvider tokenProvider;
    private final UserDetailsServiceImpl userDetailsService;
    private final AuthenticationManager authenticationManager;

    @Override
    public Filter createFilter() {
        return new JwtAuthenticationFilter(tokenProvider, userDetailsService);
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User userDetails = (User) authentication.getPrincipal();
        String jwtToken = tokenProvider.generateToken(authentication);

        return AuthResponse.builder()
                .token(jwtToken)
                .userId(userDetails.getId())
                .email(userDetails.getEmail())
                .namaLengkap(userDetails.getNamaLengkap())
                .role(userDetails.getRole().name())
                .build();
    }
}
