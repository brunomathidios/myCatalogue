package org.sid.repository;

import org.sid.entities.Produit;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ProduitRepository extends JpaRepository<Produit, Long> {
	
	Page<Produit> findByDesignationContainsIgnoreCase(String mc, Pageable pageable);
	
	@Query("select p from Produit p where p.designation like :x and p.prix > :y")
	Page<Produit> chercher(@Param("x") String mc, @Param("y") double prixMin, Pageable pageable);

}
