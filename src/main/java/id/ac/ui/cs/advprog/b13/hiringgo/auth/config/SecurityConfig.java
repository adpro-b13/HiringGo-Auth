package id.ac.ui.cs.advprog.b13.hiringgo.auth.config;

// import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.JwtAuthenticationFilter; // Akan dibuat nanti
import lombok.RequiredArgsConstructor;
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
import org.springframework.security.core.userdetails.UserDetailsService; // Import UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter; // Akan digunakan saat filter JWT ada

@Configuration // Menandakan kelas ini sebagai sumber konfigurasi bean
@EnableWebSecurity // Mengaktifkan dukungan keamanan web Spring
@EnableMethodSecurity(prePostEnabled = true) // Mengaktifkan keamanan berbasis metode (misal @PreAuthorize)
@RequiredArgsConstructor
public class SecurityConfig {

    // private final JwtAuthenticationFilter jwtAuthenticationFilter; // Akan di-inject nanti
    private final UserDetailsService userDetailsService; // Akan di-inject dari UserDetailsServiceImpl yang akan kita buat

    @Bean // Mendefinisikan bean PasswordEncoder
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Menggunakan BCrypt sebagai algoritma hashing
    }

    @Bean // Mendefinisikan bean AuthenticationManager
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean // Mendefinisikan bean AuthenticationProvider
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService); // Set UserDetailsService kustom kita
        authProvider.setPasswordEncoder(passwordEncoder()); // Set PasswordEncoder yang kita definisikan
        return authProvider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Nonaktifkan CSRF karena kita akan pakai JWT (stateless)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(
                                "/api/auth/**", // Endpoint registrasi & login publik
                                // Tambahkan path lain yang ingin publik di sini
                                "/v3/api-docs/**", // OpenAPI docs jika digunakan
                                "/swagger-ui/**",   // Swagger UI jika digunakan
                                "/swagger-ui.html"
                        ).permitAll()
                        // .requestMatchers("/api/admin/**").hasRole("ADMIN") // Contoh proteksi berdasarkan role
                        // .requestMatchers("/api/dosen/**").hasAnyRole("DOSEN", "ADMIN")
                        // .requestMatchers("/api/mahasiswa/**").hasAnyRole("MAHASISWA", "ADMIN")
                        .anyRequest().authenticated() // Semua request lain butuh autentikasi
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Buat sesi stateless untuk JWT
                )
                .authenticationProvider(authenticationProvider()); // Set AuthenticationProvider kustom kita
        // .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); // Akan ditambahkan saat filter JWT siap

        return http.build();
    }
}