 package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.dto.LoginRequest;

import jakarta.servlet.Filter;

public interface AuthenticationStrategy {
    Filter createFilter(); // Setiap strategi akan membuat filter spesifiknya
    AuthResponse login(LoginRequest request);
}