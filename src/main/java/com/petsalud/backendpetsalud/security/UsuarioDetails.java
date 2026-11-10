package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.entity.Rol;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.List;

public class UsuarioDetails implements UserDetails {
    private final Usuario usuario;
    public UsuarioDetails(Usuario usuario) { this.usuario = usuario; }
    @Override public Collection<? extends GrantedAuthority> getAuthorities() {
        Rol rol = usuario.getRol();
        // Compatibilidad con roles preexistentes del backend original.
        if (rol == Rol.ADMIN) return List.of(new SimpleGrantedAuthority("GERENTE"));
        if (rol == Rol.VETERINARIO) return List.of(new SimpleGrantedAuthority("EMPLEADO"));
        return List.of(new SimpleGrantedAuthority(rol.name()));
    }
    @Override public String getPassword() { return usuario.getPassword(); }
    @Override public String getUsername() { return usuario.getEmail(); }
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }
}
