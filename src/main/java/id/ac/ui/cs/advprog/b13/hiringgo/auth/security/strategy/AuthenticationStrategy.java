 package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.strategy;

import jakarta.servlet.Filter;

public interface AuthenticationStrategy {
    Filter createFilter(); // Setiap strategi akan membuat filter spesifiknya
}