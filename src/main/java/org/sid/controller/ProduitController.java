package org.sid.controller;

import org.sid.entities.Produit;
import org.sid.pojo.AuthUser;
import org.sid.repository.ProduitRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ProduitController {
	
	@Autowired
	private ProduitRepository produitRepository;

	@GetMapping(path = "/produits")
	public String produits(Model model,
			@RequestParam(name = "page", defaultValue = "0") int page,
			@RequestParam(name = "size", defaultValue = "5") int size,
			@RequestParam(name = "motCle", defaultValue = "") String motCle) {
		
		Page<Produit> pageProduits = 
				this.produitRepository.findByDesignationContainsIgnoreCase(motCle, PageRequest.of(page, size));
		
		model.addAttribute("pageProduits", pageProduits);
		model.addAttribute("currentPage", page);
		model.addAttribute("size", size);
		model.addAttribute("motCle", motCle);
		model.addAttribute("pages", new int[pageProduits.getTotalPages()]);
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		AuthUser loggedUser = (AuthUser) authentication.getPrincipal();
		
		model.addAttribute("nomUtilisateur", loggedUser.getUtilisateur().getNom());
		
		return "produits";
	}
	
	@PostMapping(path = "/deleteProduits")
	public String delete(Long id, String motCle, String page, String size) {
		this.produitRepository.deleteById(id);
		return "redirect:/produits?page="+page+"&motCle="+motCle+"&size"+size;
	}
}
