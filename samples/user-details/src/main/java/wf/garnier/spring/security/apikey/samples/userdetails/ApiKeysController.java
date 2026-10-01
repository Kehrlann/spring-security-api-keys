/*
 * Copyright 2026-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package wf.garnier.spring.security.apikey.samples.userdetails;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import wf.garnier.spring.security.apikey.GeneratedApiKey;

/**
 * Lets a user list, create and delete their own API keys.
 */
@Controller
class ApiKeysController {

	private final UserApiKeyRepository apiKeyRepository;

	ApiKeysController(UserApiKeyRepository apiKeyRepository) {
		this.apiKeyRepository = apiKeyRepository;
	}

	@GetMapping("/")
	String apiKeys(@AuthenticationPrincipal UserDetails user, Model model) {
		model.addAttribute("username", user.getUsername());
		model.addAttribute("roles", roles(user));
		model.addAttribute("apiKeys", this.apiKeyRepository.findByPrincipalName(user.getUsername()));
		return "api-keys";
	}

	@PostMapping("/api-keys")
	String create(@AuthenticationPrincipal UserDetails user, @RequestParam String label,
			@RequestParam(defaultValue = "") List<String> roles, RedirectAttributes redirectAttributes) {
		// A key can only carry roles its owner has
		List<GrantedAuthority> authorities = user.getAuthorities()
			.stream()
			.filter((authority) -> roles.contains(authority.getAuthority()))
			.map(GrantedAuthority.class::cast)
			.toList();
		GeneratedApiKey apiKey = this.apiKeyRepository.generate(user.getUsername(),
				StringUtils.hasText(label) ? label.strip() : "API key", authorities);
		// Shown once, never stored in plaintext
		redirectAttributes.addFlashAttribute("newApiKey", apiKey.getUserFacingApiKey());
		return "redirect:/";
	}

	@PostMapping("/api-keys/{id}/delete")
	String delete(@AuthenticationPrincipal UserDetails user, @PathVariable String id) {
		this.apiKeyRepository.delete(user.getUsername(), id);
		return "redirect:/";
	}

	private static List<String> roles(UserDetails user) {
		return user.getAuthorities()
			.stream()
			.map(GrantedAuthority::getAuthority)
			.filter((authority) -> authority != null && authority.startsWith("ROLE_"))
			.toList();
	}

}
