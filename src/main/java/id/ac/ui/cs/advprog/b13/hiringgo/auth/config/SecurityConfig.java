package id.ac.ui.cs.advprog.b13.hiringgo.auth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier; // Pastikan import ini ada
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.factory.AuthenticationStrategyFactory;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy.AuthenticationStrategy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor // Ini akan meng-inject field final
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    // Inject factory spesifik. Gunakan @Qualifier jika ada beberapa factory dengan tipe yang sama.
    // Nama qualifier harus sama dengan nama bean yang didefinisikan di JwtStrategyFactory ("jwtStrategyFactory")
    @Qualifier("jwtStrategyFactory")
    private final AuthenticationStrategyFactory jwtAuthFactory; // Jadikan final agar di-inject oleh Lombok

    // ... (Bean PasswordEncoder, AuthenticationManager, AuthenticationProvider tetap sama) ...
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationStrategy jwtStrategy = jwtAuthFactory.createStrategy();

        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(
                                "/api/auth/**",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/actuator/health",
                                "/actuator/info",
                                "/actuator/prometheus"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtStrategy.createFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}