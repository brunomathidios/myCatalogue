package org.sid.service;

import org.sid.pojo.AuthUser;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface UtilisateurService {

	AuthUser loadUserByUsername(String userName) throws UsernameNotFoundException;
}
