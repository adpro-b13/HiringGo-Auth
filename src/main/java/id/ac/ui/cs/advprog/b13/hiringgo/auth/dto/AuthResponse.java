package id.ac.ui.cs.advprog.b13.hiringgo.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String token; // JWT Token
    private String email;
    private String role;
    private String namaLengkap;
    private Long userId; // Opsional: ID pengguna
}