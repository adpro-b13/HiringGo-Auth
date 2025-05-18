package id.ac.ui.cs.advprog.b13.hiringgo.auth.model;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RoleTest {

    @Test
    void testRoleEnumValuesExist() {
        // Memastikan semua nilai enum yang diharapkan ada
        assertNotNull(Role.valueOf("MAHASISWA"));
        assertNotNull(Role.valueOf("DOSEN"));
        assertNotNull(Role.valueOf("ADMIN"));
    }

    @Test
    void testRoleEnumToString() {
        // Memastikan representasi String dari enum sesuai dengan namanya
        assertEquals("MAHASISWA", Role.MAHASISWA.toString());
        assertEquals("DOSEN", Role.DOSEN.toString());
        assertEquals("ADMIN", Role.ADMIN.toString());
    }

    @Test
    void testRoleEnumCanBeAccessed() {
        // Contoh penggunaan
        Role roleMahasiswa = Role.MAHASISWA;
        assertSame(Role.MAHASISWA, roleMahasiswa);
    }
}

