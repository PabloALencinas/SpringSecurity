package com.pabloagustin.security.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

// Lombok for getters, setters and constructors and Entity annotation
// Entity
// Table Annotation for out psql database
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
// Do not forget the underscore because you will get an error!
@Table(name = "_user")
public class User implements UserDetails {
	// Model for USER
	@Id
	@GeneratedValue
	private Integer id;
	private String firstname;
	private String lastname;
	private String email;
	private String password;
	// Let's create a Role class to take control of roles in our application
	@Enumerated(EnumType.STRING)
	private Role role;

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return List.of(new SimpleGrantedAuthority(role.name()));
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return email;
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
