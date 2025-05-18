package id.ac.ui.cs.advprog.b13.hiringgo.auth.service;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.RegisterRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.Role;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.repository.UserRepository;
// import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider; // Akan kita buat nanti

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager; // Akan di-inject nanti
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder; // Untuk menyimpan Authentication setelah login
import org.springframework.security.crypto.password.PasswordEncoder; // Akan di-inject nanti
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional; // Untuk manajemen transaksi

@Service // Menandakan bahwa kelas ini adalah komponen Spring Service
@RequiredArgsConstructor // Lombok: Membuat constructor dengan semua field final yang di-inject
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder; // Akan di-inject oleh Spring Security config
    private final AuthenticationManager authenticationManager; // Akan di-inject oleh Spring Security config
    // private final JwtTokenProvider jwtTokenProvider; // Akan kita buat dan inject nanti

    @Override
    @Transactional // Memastikan operasi database berjalan dalam satu transaksi
    public String registerMahasiswa(RegisterRequest request) {
        // 1. Validasi Input (sebagian sudah ada di NFR, sebagian bisa di sini)
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Error: Email sudah terdaftar!");
        }
        if (request.getNim() == null || request.getNim().isBlank()) {
            throw new IllegalArgumentException("Error: NIM tidak boleh kosong untuk mahasiswa!");
        }
        if (userRepository.existsByNim(request.getNim())) {
            throw new IllegalArgumentException("Error: NIM sudah terdaftar!");
        }
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Error: Password dan konfirmasi password tidak cocok!");
        }
        // Validasi kekuatan password (NFR: kombinasi huruf kapital, angka, minimal 8 karakter)
        // Bisa ditambahkan di sini atau menggunakan validator terpisah.
        // Contoh sederhana:
        if (request.getPassword().length() < 8) {
            throw new IllegalArgumentException("Error: Password minimal 8 karakter!");
        }
        // Implementasi validasi regex untuk kekuatan password yang lebih baik bisa ditambahkan.


        // 2. Buat objek User baru
        User user = User.builder()
                .namaLengkap(request.getNamaLengkap())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) // Hashing password!
                .role(Role.MAHASISWA) // Sesuai use case, registrasi awal adalah Mahasiswa
                .nim(request.getNim())
                .build();

        // 3. Simpan User ke database
        userRepository.save(user);

        return "Pendaftaran Akun Sukses!"; // Sesuai pesan di use case
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        // 1. Autentikasi menggunakan AuthenticationManager dari Spring Security
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // 2. Jika autentikasi berhasil, set Authentication ke SecurityContext
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 3. Dapatkan detail User dari Principal
        User userDetails = (User) authentication.getPrincipal();

        // 4. Generate JWT Token (ini akan memerlukan JwtTokenProvider)
        // String jwtToken = jwtTokenProvider.generateToken(authentication); // Atau generateTokenFromUser(userDetails)
        // Untuk sementara, kita set token dummy karena JwtTokenProvider belum dibuat
        String jwtToken = "dummy-jwt-token-akan-diganti-nanti";


        // 5. Buat AuthResponse
        return AuthResponse.builder()
                .token(jwtToken)
                .userId(userDetails.getId())
                .email(userDetails.getEmail())
                .namaLengkap(userDetails.getNamaLengkap())
                .role(userDetails.getRole().name())
                .build();
    }
}