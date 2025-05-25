package id.ac.ui.cs.advprog.b13.hiringgo.auth.service;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.RegisterRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.Role;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.repository.UserRepository;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider; // IMPORT INI
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor // Ini akan meng-inject field final
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider; // JADIKAN FINAL dan akan di-inject

    @Override
    @Transactional
    public String registerUser(RegisterRequest request) {
        // ... (Logika registrasi sudah benar) ...
        // 1. Validasi Umum Awal (yang tidak bergantung pada role spesifik untuk NIM/NIP)
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Error: Email sudah terdaftar!");
        }
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Error: Password dan konfirmasi password tidak cocok!");
        }
        if (request.getPassword().length() < 8) {
            throw new IllegalArgumentException("Error: Password minimal 8 karakter!");
        }
        if (request.getRole() == null) { // Tambahan validasi untuk role
            throw new IllegalArgumentException("Error: Role tidak boleh kosong.");
        }

        // Persiapkan builder, tapi JANGAN set password yang di-encode dulu
        User.UserBuilder userBuilder = User.builder()
                .namaLengkap(request.getNamaLengkap())
                .email(request.getEmail())
                .role(request.getRole());

        // 2. Validasi dan Setup Spesifik Role
        if (request.getRole() == Role.MAHASISWA) {
            if (request.getNim() == null || request.getNim().isBlank()) {
                throw new IllegalArgumentException("Error: NIM tidak boleh kosong untuk mahasiswa!");
            }
            if (userRepository.existsByNim(request.getNim())) {
                throw new IllegalArgumentException("Error: NIM sudah terdaftar!");
            }
            userBuilder.nim(request.getNim());
        } else if (request.getRole() == Role.DOSEN) {
            throw new IllegalArgumentException("Error: Registrasi sebagai DOSEN tidak diizinkan melalui endpoint ini.");
        } else if (request.getRole() == Role.ADMIN) {
            throw new IllegalArgumentException("Error: Registrasi sebagai ADMIN tidak diizinkan melalui endpoint ini.");
        } else {
            throw new IllegalArgumentException("Error: Role tidak valid atau tidak didukung.");
        }

        // Baru encode password SETELAH semua validasi di atas lolos
        userBuilder.password(passwordEncoder.encode(request.getPassword()));

        // 3. Buat objek User dan Simpan ke database
        User user = userBuilder.build();
        userRepository.save(user);

        return "Pendaftaran Akun " + request.getRole().name() + " Sukses!";
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        User userDetails = (User) authentication.getPrincipal();
        // String jwtToken = "dummy-jwt-token-akan-diganti-nanti"; // Hapus placeholder
        String jwtToken = jwtTokenProvider.generateToken(authentication); // GUNAKAN JwtTokenProvider

        return AuthResponse.builder()
                .token(jwtToken) // Token asli
                .userId(userDetails.getId())
                .email(userDetails.getEmail())
                .namaLengkap(userDetails.getNamaLengkap())
                .role(userDetails.getRole().name())
                .build();
    }
}