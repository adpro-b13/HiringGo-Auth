package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User; // Atau UserDetails jika lebih generik
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    @Value("${app.jwtSecret}")
    private String jwtSecretString;

    @Value("${app.jwtExpirationMs}")
    private int jwtExpirationMs;

    private SecretKey jwtSecretKey;

    @PostConstruct
    public void init() {
        // Konversi string secret ke SecretKey.
        // Pastikan secret cukup panjang dan aman (minimal 256 bit untuk HS256, 384 untuk HS384, 512 untuk HS512).
        this.jwtSecretKey = Keys.hmacShaKeyFor(jwtSecretString.getBytes());
        // Jika panjang secret tidak sesuai, Keys.hmacShaKeyFor akan melempar error.
    }

    public String generateToken(Authentication authentication) {
        // Lebih baik menggunakan UserDetails dari Spring Security jika memungkinkan,
        // tapi karena User model kita sudah implement UserDetails, ini juga valid.
        User userPrincipal = (User) authentication.getPrincipal();
        String roles = userPrincipal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(",")); // Simpan roles sebagai string dipisahkan koma

        return Jwts.builder()
                .setSubject(userPrincipal.getUsername()) // Ini adalah email
                .claim("userId", userPrincipal.getId())
                .claim("namaLengkap", userPrincipal.getNamaLengkap())
                .claim("roles", roles) // Tambahkan roles
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(jwtSecretKey) // Sesuaikan algoritma jika perlu
                .compact();
    }

    // Overload method untuk generate token langsung dari objek User (jika diperlukan)
    public String generateToken(User userDetails) {
        String roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .setSubject(userDetails.getUsername()) // email
                .claim("userId", userDetails.getId())
                .claim("namaLengkap", userDetails.getNamaLengkap())
                .claim("roles", roles)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(jwtSecretKey)
                .compact();
    }

    public String getUsernameFromJwt(String token) { // Mengembalikan email
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecretKey).build().parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token: {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            logger.error("JWT token is expired: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            logger.error("JWT token is unsupported: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty: {}", ex.getMessage());
        }
        // io.jsonwebtoken.security.SecurityException akan dilempar jika key tidak valid
        // tapi Keys.hmacShaKeyFor seharusnya sudah menangani pembuatan key yang valid dari string.
        return false;
    }
}