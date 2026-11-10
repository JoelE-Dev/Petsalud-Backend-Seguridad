package com.petsalud.backendpetsalud.security;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {
    @Test void generaYValidaToken() {
        JwtUtil jwt = new JwtUtil("clave-de-prueba-aleatoria-para-jwt-de-32-bytes-minimo", 60000);
        String token = jwt.generarToken("cliente@ejemplo.cl");
        assertTrue(jwt.esValido(token));
        assertEquals("cliente@ejemplo.cl", jwt.obtenerEmail(token));
        assertFalse(jwt.esValido(token + "alterado"));
    }
    @Test void rechazaClaveCorta() {
        assertThrows(IllegalArgumentException.class, () -> new JwtUtil("corta", 60000));
    }
}
