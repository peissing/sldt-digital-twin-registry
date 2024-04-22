/**
 * File:     $HeadURL$
 * Revision: $Revision$
 * Checkin user: $Author$
 * Checkin date: $Date$
 */

package org.eclipse.tractusx.semantics.registry.security;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * @author peissing
 *
 */
public final class KeycloakAuthorizationEvaluator extends AuthorizationEvaluator {

	/**
	 * Constructor
	 * @param clientId clientId
	 */
	public KeycloakAuthorizationEvaluator(String clientId) {
		super(clientId);
	}

	   protected boolean containsRole( String role ) {
		      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		      if ( !(authentication instanceof JwtAuthenticationToken) ) {
		         return false;
		      }

		      JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) (authentication);
		      Map<String, Object> claims = jwtAuthenticationToken.getToken().getClaims();

		      Object resourceAccess = claims.get( "resource_access" );
		      if ( !(resourceAccess instanceof Map) ) {
		         return false;
		      }

		      Object resource = ((Map<String, Object>) resourceAccess).get( this.getClientId() );
		      if ( !(resource instanceof Map) ) {
		         return false;
		      }

		      Object roles = ((Map<String, Object>) resource).get( "roles" );
		      if ( !(roles instanceof Collection) ) {
		         return false;
		      }

		      Collection<String> rolesList = (Collection<String>) roles;
		      return rolesList.contains( role );
		   }
}
