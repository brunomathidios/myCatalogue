package org.sid.service.impl;

import java.util.Optional;

import org.sid.entities.Utilisateur;
import org.sid.pojo.AuthUser;
import org.sid.repository.UtilisateurRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service(value = "utilisateurService")
public class UtilisateurServiceImpl implements UserDetailsService {

	@Autowired
	private UtilisateurRepository repository;
	
	@Override
	public UserDetails loadUserByUsername(String login) {
		final Optional<Utilisateur> utilisateur = this.repository.findByLogin(login);

	      if ( utilisateur.isPresent() ) {

	          final AuthUser authUser = new AuthUser(utilisateur.get());
	          
	          authUser.getUtilisateur().setNom( utilisateur.get().getNom() );
	           
	          return authUser;
	      }

	      throw new UsernameNotFoundException("Utilisateur non trouvé!");
	}

}
