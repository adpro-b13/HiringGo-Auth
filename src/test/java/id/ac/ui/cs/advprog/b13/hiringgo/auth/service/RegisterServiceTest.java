class RegisterServiceTest {

    @Mock
    UserRepository userRepository;

    @InjectMocks
    RegisterServiceImpl registerService;

    RegisterRequest request;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        request = RegisterRequest.builder()
                .fullName("John Doe")
                .nim("123456789")
                .email("john.doe@example.com")
                .password("password123")
                .confirmPassword("password123")
                .build();
    }

    @Test
    void testRegisterFailsWhenEmailTaken() {
        when(userRepository.existsByEmail(request.getEmail())).thenReturn(true);

        ApiException ex = assertThrows(ApiException.class, () -> {
            registerService.register(request);
        });

        assertEquals(4001, ex.getErrorCode());
    }

    @Test
    void testRegisterFailsWhenNimTaken() {
        when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
        when(userRepository.existsByNim(request.getNim())).thenReturn(true);

        ApiException ex = assertThrows(ApiException.class, () -> {
            registerService.register(request);
        });

        assertEquals(4002, ex.getErrorCode());
    }

    @Test
    void testRegisterFailsWhenPasswordMismatch() {
        request.setConfirmPassword("mismatch");

        ApiException ex = assertThrows(ApiException.class, () -> {
            registerService.register(request);
        });

        assertEquals(4003, ex.getErrorCode());
    }

    @Test
    void testRegisterSuccess() {
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(userRepository.existsByNim(anyString())).thenReturn(false);
        when(userRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        User result = registerService.register(request);

        assertEquals("john.doe@example.com", result.getEmail());
        assertEquals(Role.MAHASISWA, result.getRole());
    }
}
