package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.factory;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy.AuthenticationStrategy;

public interface AuthenticationStrategyFactory {
    AuthenticationStrategy createStrategy();
    // Bisa juga menerima parameter jika pembuatan strategi bergantung pada konfigurasi
    // AuthenticationStrategy createStrategy(Map<String, Object> options);
}