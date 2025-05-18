package id.ac.ui.cs.advprog.b13.hiringgo.auth.service;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.RegisterRequest;

public interface AuthService {
    /**
     * Mendaftarkan pengguna baru sebagai Mahasiswa.
     *
     * @param request Data registrasi dari pengguna.
     * @return Pesan sukses atau melempar exception jika gagal.
     * @throws IllegalArgumentException jika input tidak valid (misal email sudah ada).
     */
    String registerMahasiswa(RegisterRequest request);

    /**
     * Melakukan proses login untuk pengguna.
     *
     * @param request Kredensial login dari pengguna.
     * @return AuthResponse yang berisi token JWT dan detail pengguna jika login berhasil.
     * @throws org.springframework.security.core.AuthenticationException jika autentikasi gagal.
     */
    AuthResponse login(LoginRequest request);

}