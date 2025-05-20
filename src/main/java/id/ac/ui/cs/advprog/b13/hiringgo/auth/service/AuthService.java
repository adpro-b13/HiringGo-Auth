package id.ac.ui.cs.advprog.b13.hiringgo.auth.service;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.RegisterRequest;

public interface AuthService {
    /**
     * Mendaftarkan pengguna baru (Mahasiswa atau Dosen).
     *
     * @param request Data registrasi dari pengguna.
     * @return Pesan sukses atau melempar exception jika gagal.
     * @throws IllegalArgumentException jika input tidak valid.
     */
    String registerUser(RegisterRequest request);

    AuthResponse login(LoginRequest request);
}