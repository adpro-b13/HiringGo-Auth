package id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.Role;
import id.ac.ui.cs.advprog.b13.hiringgo.auth.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;

import id.ac.ui.cs.advprog.b13.hiringgo.auth.security.jwt.JwtTokenProvider;

import javax.crypto.SecretKey;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtTokenProviderTest {

    @InjectMocks
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private Authentication authentication;

    private User userDetails;
    // Use a strong secret for testing, matching typical key length requirements (e.g., 256 bits for HS256)
    private final String testSecret = "testSecretKeyForJwtTokenProviderTestingPurposeOnly0123456789ABCDEF0123456789ABCDEF"; // 64 chars
    private final int jwtExpirationMs = 3600000; // 1 hour
    private SecretKey actualSecretKey;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtTokenProvider, "jwtSecretString", testSecret);
        ReflectionTestUtils.setField(jwtTokenProvider, "jwtExpirationMs", jwtExpirationMs);
        jwtTokenProvider.init(); // Manually call @PostConstruct method to initialize jwtSecretKey in JwtTokenProvider

        // This key is used for local verification or manual token creation in tests
        actualSecretKey = Keys.hmacShaKeyFor(testSecret.getBytes());

        userDetails = User.builder()
                .id(1L)
                .email("testuser@example.com")
                .namaLengkap("Test User")
                .role(Role.MAHASISWA)
                .password("password") // Not directly used by token generation's core logic but good for User object completeness
                .build();
    }

    @Test
    void testInit_Success() {
        // Verify that jwtSecretKey is initialized after init()
        SecretKey internalKey = (SecretKey) ReflectionTestUtils.getField(jwtTokenProvider, "jwtSecretKey");
        assertNotNull(internalKey);
        assertEquals(actualSecretKey.getAlgorithm(), internalKey.getAlgorithm());
        assertArrayEquals(actualSecretKey.getEncoded(), internalKey.getEncoded());
    }

    @Test
    void testGenerateToken_WithAuthentication() {
        when(authentication.getPrincipal()).thenReturn(userDetails);

        String token = jwtTokenProvider.generateToken(authentication);

        assertNotNull(token);
        Claims claims = Jwts.parser().setSigningKey(actualSecretKey).build().parseClaimsJws(token).getBody();
        assertEquals(userDetails.getUsername(), claims.getSubject()); // email
        assertEquals(userDetails.getId(), claims.get("userId", Long.class));
        assertEquals(userDetails.getNamaLengkap(), claims.get("namaLengkap", String.class));
        assertEquals("ROLE_" + userDetails.getRole().name(), claims.get("roles", String.class));
        assertTrue(claims.getExpiration().after(new Date()));
        assertTrue(claims.getIssuedAt().before(new Date(System.currentTimeMillis() + 1000))); // Issued recently
    }

    @Test
    void testGenerateToken_WithUserDetails() {
        String token = jwtTokenProvider.generateToken(userDetails);

        assertNotNull(token);
        Claims claims = Jwts.parser().setSigningKey(actualSecretKey).build().parseClaimsJws(token).getBody();
        assertEquals(userDetails.getUsername(), claims.getSubject()); // email
        assertEquals(userDetails.getId(), claims.get("userId", Long.class));
        assertEquals(userDetails.getNamaLengkap(), claims.get("namaLengkap", String.class));
        assertEquals("ROLE_" + userDetails.getRole().name(), claims.get("roles", String.class));
        assertTrue(claims.getExpiration().after(new Date()));
    }

    @Test
    void testGetUsernameFromJwt() {
        String token = jwtTokenProvider.generateToken(userDetails);
        String username = jwtTokenProvider.getUsernameFromJwt(token);
        assertEquals(userDetails.getEmail(), username);
    }

    @Test
    void testGetAllClaimsFromToken() {
        String token = jwtTokenProvider.generateToken(userDetails);
        Claims claims = jwtTokenProvider.getAllClaimsFromToken(token);

        assertNotNull(claims);
        assertEquals(userDetails.getUsername(), claims.getSubject());
        assertEquals(userDetails.getId(), claims.get("userId", Long.class));
        assertEquals(userDetails.getNamaLengkap(), claims.get("namaLengkap", String.class));
        assertEquals("ROLE_" + userDetails.getRole().name(), claims.get("roles", String.class));
    }

    @Test
    void testValidateToken_ValidToken() {
        String token = jwtTokenProvider.generateToken(userDetails);
        assertTrue(jwtTokenProvider.validateToken(token));
    }

    @Test
    void testValidateToken_ExpiredToken() {
        Date now = new Date();
        // Create a token that expired 10 seconds ago
        String expiredToken = Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(now.getTime() - 20000)) // Issued 20 seconds ago
                .setExpiration(new Date(now.getTime() - 10000)) // Expired 10 seconds ago
                .signWith(actualSecretKey)
                .compact();

        assertFalse(jwtTokenProvider.validateToken(expiredToken));
        // We expect "JWT token is expired" to be logged by the provider
    }

    @Test
    void testValidateToken_MalformedToken_RandomString() {
        String malformedToken = "this.is.not.a.valid.jwt.token";
        assertFalse(jwtTokenProvider.validateToken(malformedToken));
        // We expect "Invalid JWT token" to be logged
    }

    @Test
    void testValidateToken_MalformedToken_Incomplete() {
        String token = jwtTokenProvider.generateToken(userDetails);
        String incompleteToken = token.substring(0, token.lastIndexOf('.')); // Remove signature part
        assertFalse(jwtTokenProvider.validateToken(incompleteToken));
        // We expect "Invalid JWT token" to be logged
    }

    @Test
    void testValidateToken_MalformedToken_AlgNone() {
        // Header: {"alg":"none"} Payload: {"sub":"testuser@example.com"} Signature: (empty)
        String algNoneToken = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0dXNlckBleGFtcGxlLmNvbSJ9.";
        // JJWT by default rejects alg=none, usually as MalformedJwtException
        assertFalse(jwtTokenProvider.validateToken(algNoneToken));
        // We expect "Invalid JWT token" (due to MalformedJwtException) to be logged
    }


    @Test
    void testValidateToken_UnsupportedToken_DifferentAlgorithmInHeader() {
        // Header: {"alg":"RS256"} Payload: {"sub":"test"} Signature: (fake)
        // Our key 'actualSecretKey' is for HMAC. This token claims RS256.
        String tokenWithUnsupportedAlgorithm = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.ZmFrZXNpZ25hdHVyZQ";
        // This is expected to throw UnsupportedJwtException because the key type (HMAC)
        // doesn't match the algorithm (RS256) claimed in the token for this parser setup.
        assertFalse(jwtTokenProvider.validateToken(tokenWithUnsupportedAlgorithm));
        // We expect "JWT token is unsupported" to be logged
    }

    @Test
    void testValidateToken_IllegalArgument_NullToken() {
        assertFalse(jwtTokenProvider.validateToken(null));
    }

    @Test
    void testValidateToken_IllegalArgument_EmptyToken() {
        assertFalse(jwtTokenProvider.validateToken(""));
    }

    @Test
    void testValidateToken_IllegalArgument_WhitespaceToken() {
        assertFalse(jwtTokenProvider.validateToken("   "));
    }

    @Test
    void testValidateToken_InvalidSignature_TokenSignedWithDifferentKey() {
        SecretKey differentSecretKey = Keys.hmacShaKeyFor("anotherDifferentSecretKeyForTestingPurposes0123456789ABCDEF0123456789ABCDEF".getBytes());
        String tokenWithWrongSignature = Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(differentSecretKey) // Signed with a different key
                .compact();

        assertThrows(SignatureException.class, () -> {
            jwtTokenProvider.validateToken(tokenWithWrongSignature);
        });
    }
}