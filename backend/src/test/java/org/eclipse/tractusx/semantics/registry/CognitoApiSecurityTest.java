/**
 * File:     $HeadURL$
 * Revision: $Revision$
 * Checkin user: $Author$
 * Checkin date: $Date$
 */

package org.eclipse.tractusx.semantics.registry;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;

/**
 * @author peissing
 *
 */
@ActiveProfiles(profiles = { "cognito-test" })
public class CognitoApiSecurityTest extends AbstractAssetAdministrationShellApi {
    @Test
    public void testWithInvalidAuthenticationTokenConfigurationExpectUnauthorized() throws Exception {
       mvc.perform(
                   MockMvcRequestBuilders
                         .get( SINGLE_SHELL_BASE_PATH, UUID.randomUUID() )
                         .accept( MediaType.APPLICATION_JSON )
                         .with( jwtTokenFactory.withoutResourceAccess() )
             )
             .andDo( MockMvcResultHandlers.print() )
             .andExpect( status().isForbidden() );

       mvc.perform(
                   MockMvcRequestBuilders
                         .get( SINGLE_SHELL_BASE_PATH, UUID.randomUUID() )
                         .accept( MediaType.APPLICATION_JSON )
                         .with( jwtTokenFactory.withoutRoles() )
             )
             .andDo( MockMvcResultHandlers.print() )
             .andExpect( status().isForbidden() );
    }

    @Test
    public void testWithAuthenticationTokenConfigurationExpectAuthorized() throws Exception {
    	// test is only if Cognito auth is working. Shell descriptor does not exist so we expect a 404 not found.
        mvc.perform(
                   MockMvcRequestBuilders
                         .get( SINGLE_SHELL_BASE_PATH, UUID.randomUUID() )
                         .accept( MediaType.APPLICATION_JSON )
                         .with( jwtTokenFactory.allRoles() )
             )
             .andDo( MockMvcResultHandlers.print() )
             .andExpect( status().isNotFound() );
    }
}
