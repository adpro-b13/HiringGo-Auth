package id.ac.ui.cs.advprog.b13.hiringgo.auth.dto;

// import jakarta.validation.constraints.Email;
// import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
    // @NotBlank
    // @Email
    private String email;

    // @NotBlank
    private String password;
}