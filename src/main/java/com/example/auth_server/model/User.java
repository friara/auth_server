package com.example.auth_server.model;


import jakarta.persistence.*;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;


@Entity
@Data
@Table(name = "Users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String login;
    private String password;

    @ManyToOne(fetch = FetchType.EAGER) // Роль будет загружаться сразу
    @JoinColumn(name = "role_id")
    private Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (role == null) {
            // Возвращаем пустую коллекцию или роль по умолчанию
            return List.of(new SimpleGrantedAuthority("ROLE_GUEST"));
        }
        return List.of(new SimpleGrantedAuthority(role.getName()));
    }

    @Override
    public String getUsername() {
        return login;
    }
    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

