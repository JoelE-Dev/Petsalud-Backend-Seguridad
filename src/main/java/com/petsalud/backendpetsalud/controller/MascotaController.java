package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.entity.Mascota;
import com.petsalud.backendpetsalud.service.MascotaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.parameters.P;
import java.util.List;

@RestController
@RequestMapping("/api/mascotas")
public class MascotaController {

    @Autowired
    private MascotaService mascotaService;

    @PreAuthorize("hasAnyAuthority('EMPLEADO','GERENTE') or @accesoUsuario.esUsuario(#propietarioId, authentication)")
    @PostMapping("/propietario/{propietarioId}")
    public ResponseEntity<Mascota> registrarMascota(@PathVariable @P("propietarioId") Long propietarioId, @RequestBody Mascota mascota) {
        Mascota nuevaMascota = mascotaService.registrarMascota(mascota, propietarioId);
        return ResponseEntity.ok(nuevaMascota);
    }

    @PreAuthorize("hasAnyAuthority('EMPLEADO','GERENTE') or @accesoUsuario.esPropietario(#id, authentication)")
    @GetMapping("/{id}")
    public ResponseEntity<Mascota> obtenerMascotaPorId(@PathVariable @P("id") Long id) {
        return mascotaService.obtenerMascotaPorId(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PreAuthorize("hasAnyAuthority('EMPLEADO','GERENTE') or @accesoUsuario.esPropietario(#id, authentication)")
    @PutMapping("/{id}")
    public ResponseEntity<Mascota> actualizarMascota(@PathVariable @P("id") Long id, @RequestBody Mascota mascota) {
        Mascota mascotaActualizada = mascotaService.actualizarMascota(id, mascota);
        return ResponseEntity.ok(mascotaActualizada);
    }

    @PreAuthorize("hasAnyAuthority('EMPLEADO','GERENTE') or @accesoUsuario.esPropietario(#id, authentication)")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> eliminarMascota(@PathVariable @P("id") Long id) {
        mascotaService.eliminarMascota(id);
        return ResponseEntity.noContent().build();
    }

    @PreAuthorize("hasAnyAuthority('EMPLEADO','GERENTE') or @accesoUsuario.esUsuario(#propietarioId, authentication)")
    @GetMapping("/propietario/{propietarioId}")
    public ResponseEntity<List<Mascota>> listarMascotasPorPropietario(@PathVariable @P("propietarioId") Long propietarioId) {
        List<Mascota> mascotas = mascotaService.listarMascotasPorPropietario(propietarioId);
        return ResponseEntity.ok(mascotas);
    }
}
