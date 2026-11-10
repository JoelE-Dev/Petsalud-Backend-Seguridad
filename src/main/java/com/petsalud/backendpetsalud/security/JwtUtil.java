package com.petsalud.backendpetsalud.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {
    private final SecretKey key;
    private final long expirationMs;

    public JwtUtil(@Value("${petsalud.jwt.secret}") String secret,
                   @Value("${petsalud.jwt.expiration-ms:3600000}") long expirationMs) {
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("Configura PETSALUD_JWT_SECRET con al menos 32 bytes aleatorios antes de iniciar el backend");
        }
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    public String generarToken(String email) {
        Date ahora = new Date();
        return Jwts.builder().subject(email).issuedAt(ahora)
                .expiration(new Date(ahora.getTime() + expirationMs))
                .signWith(key).compact();
    }

    public String obtenerEmail(String jwt) {
        Claims claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(jwt).getPayload();
        return claims.getSubject();
    }

    public boolean esValido(String jwt) {
        try { return obtenerEmail(jwt) != null; }
        catch (JwtException | IllegalArgumentException ex) { return false; }
    }
}
