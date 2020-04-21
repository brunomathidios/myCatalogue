package org.sid.pojo;

import java.util.Collection;

import org.sid.entities.Utilisateur;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class AuthUser implements UserDetails {

	private Utilisateur utilisateur;
	
	public AuthUser(Utilisateur utilisateur) {
		this.utilisateur = utilisateur;
	}
	
	@Override
    public String getUsername() {
        return this.utilisateur.getLogin();
    }

    @Override
    public String getPassword() {
        return this.utilisateur.getMotPasse();
    }

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return null;
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
