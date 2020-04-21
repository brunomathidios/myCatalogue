package org.sid.repository;

import java.util.Optional;

import org.sid.entities.Utilisateur;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UtilisateurRepository extends JpaRepository<Utilisateur, Long> {
	
	Optional<Utilisateur> findByLogin(String login);
	

}
