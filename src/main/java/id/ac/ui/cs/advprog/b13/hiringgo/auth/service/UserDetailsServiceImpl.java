package id.ac.ui.cs.advprog.b13.hiringgo.auth.service; // Atau id.ac.ui.cs.advprog.b13.hiringgo.auth.security

import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service // Menandakan ini sebagai Spring service bean
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // Cari user berdasarkan email dari repository
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
        return user; // Objek User kita sudah mengimplementasikan UserDetails
    }
}