package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import com.petsalud.backendpetsalud.repository.MascotaRepository;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component("accesoUsuario")
public class AccesoUsuario {
    private final UsuarioRepository usuarios;
    private final MascotaRepository mascotas;
    public AccesoUsuario(UsuarioRepository usuarios, MascotaRepository mascotas) {
        this.usuarios = usuarios;
        this.mascotas = mascotas;
    }
    public boolean esUsuario(Long usuarioId, Authentication auth) {
        return auth != null && auth.isAuthenticated() && usuarios.findById(usuarioId)
                .map(u -> u.getEmail().equalsIgnoreCase(auth.getName())).orElse(false);
    }
    public boolean esPropietario(Long mascotaId, Authentication auth) {
        return auth != null && auth.isAuthenticated() && mascotas.findById(mascotaId)
                .map(m -> m.getPropietario() != null &&
                        m.getPropietario().getEmail().equalsIgnoreCase(auth.getName())).orElse(false);
    }
}
