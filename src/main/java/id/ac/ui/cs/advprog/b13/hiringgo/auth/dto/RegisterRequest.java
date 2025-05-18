package id.ac.ui.cs.advprog.b13.hiringgo.auth.dto;

// Import untuk validasi jika diperlukan nanti di controller
// import jakarta.validation.constraints.Email;
// import jakarta.validation.constraints.NotBlank;
// import jakarta.validation.constraints.Size;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    // @NotBlank (akan ditambahkan validasi di controller)
    private String namaLengkap;

    // @NotBlank
    // @Email
    private String email;

    // @NotBlank
    // @Size(min = 8) // Sesuai NFR password minimal 8 karakter
    private String password;

    private String confirmPassword; // Untuk validasi di service
    private String nim;
    private String nip;
}