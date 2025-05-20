package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtAuthenticationFilter;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.service.UserDetailsServiceImpl; // atau UserDetailsService
import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor // Constructor akan di-handle oleh Factory
public class JwtAuthenticationStrategy implements AuthenticationStrategy {

    private final JwtTokenProvider tokenProvider;
    private final UserDetailsServiceImpl userDetailsService; // atau UserDetailsService

    @Override
    public Filter createFilter() {
        // Membuat instance JwtAuthenticationFilter secara manual dengan dependensi yang dibutuhkan
        return new JwtAuthenticationFilter(tokenProvider, userDetailsService);
    }
}