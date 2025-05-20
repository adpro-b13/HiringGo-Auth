package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.service.UserDetailsServiceImpl; // atau UserDetailsService jika kamu lebih suka interface
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
// import org.springframework.beans.factory.annotation.Autowired; // Hapus jika tidak @Component
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component; // Hapus jika tidak @Component
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Hapus @Component jika filter ini dibuat oleh JwtAuthenticationStrategy
// @Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    // Hapus @Autowired jika di-inject via constructor
    // @Autowired
    private final JwtTokenProvider tokenProvider;

    // Hapus @Autowired jika di-inject via constructor
    // @Autowired
    private final UserDetailsServiceImpl userDetailsService; // Atau UserDetailsService

    // Constructor untuk Dependency Injection jika tidak menggunakan @Autowired
    public JwtAuthenticationFilter(JwtTokenProvider tokenProvider, UserDetailsServiceImpl userDetailsService) {
        this.tokenProvider = tokenProvider;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                String usernameOrEmail = tokenProvider.getUsernameFromJwt(jwt); // Ini adalah email

                UserDetails userDetails = userDetailsService.loadUserByUsername(usernameOrEmail);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            // Log error tapi jangan sampai request gagal hanya karena masalah parsing token yang tidak valid
            // Spring Security akan menangani jika tidak ada Authentication di context untuk endpoint yang diproteksi
            logger.error("Could not set user authentication in security context: {}", ex.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}