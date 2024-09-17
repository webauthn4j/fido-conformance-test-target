package com.webauthn4j.fido.server.endpoint;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.async.WebAuthnAuthenticationAsyncManager;
import com.webauthn4j.async.WebAuthnRegistrationAsyncManager;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.fido.server.service.CredentialRecordService;
import com.webauthn4j.fido.server.validator.ServerPublicKeyCredentialValidator;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Path("/webauthn/assertion")
public class AssertionEndpoint {

    private final ObjectConverter objectConverter;
    private final CredentialRecordService credentialRecordService;
    private final ServerPublicKeyCredentialValidator<ServerAuthenticatorAssertionResponse> serverPublicKeyCredentialValidator = new ServerPublicKeyCredentialValidator<>();
    private final TypeReference<ServerPublicKeyCredential<ServerAuthenticatorAssertionResponse>> credentialTypeRef = new TypeReference<>() {};

    private final WebAuthnAuthenticationAsyncManager webAuthnAuthenticationAsyncManager;
    private final CollectedClientDataConverter collectedClientDataConverter;

    public AssertionEndpoint(ObjectConverter objectConverter, CredentialRecordService credentialRecordService) {
        this.objectConverter = objectConverter;
        this.webAuthnAuthenticationAsyncManager = new WebAuthnAuthenticationAsyncManager(Collections.emptyList(), objectConverter);
        this.collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
        this.credentialRecordService = credentialRecordService;
    }

    @Path("/options")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public String options(@Context HttpServletRequest httpServletRequest) throws IOException {
        HttpSession session = httpServletRequest.getSession();

        ServerPublicKeyCredentialGetOptionsRequest serverRequest = objectConverter.getJsonConverter().readValue(httpServletRequest.getInputStream(), ServerPublicKeyCredentialGetOptionsRequest.class);

        Challenge challenge = new DefaultChallenge();
        session.setAttribute("challenge", challenge.getValue());
        session.setAttribute("uv", serverRequest.getUserVerification().getValue());

        String username = serverRequest.getUsername();

        List<ServerPublicKeyCredentialDescriptor> allowedCredentials =
                credentialRecordService.get(username).stream()
                        .map( credentialRecord -> new ServerPublicKeyCredentialDescriptor(Base64UrlUtil.encodeToString(credentialRecord.getAttestedCredentialData().getCredentialId()))).toList();

        String rpId = httpServletRequest.getServerName();


        ServerPublicKeyCredentialGetOptionsResponse serverPublicKeyCredentialGetOptionsResponse = new ServerPublicKeyCredentialGetOptionsResponse(
                Base64UrlUtil.encodeToString(challenge.getValue()),
                1000L,
                rpId,
                allowedCredentials,
                serverRequest.getUserVerification(),
                serverRequest.getExtensions());

        return objectConverter.getJsonConverter().writeValueAsString(serverPublicKeyCredentialGetOptionsResponse);
    }

    @Path("/result")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public String result(@Context HttpServletRequest httpServletRequest) throws IOException {

        HttpSession session = httpServletRequest.getSession();

        ServerPublicKeyCredential<ServerAuthenticatorAssertionResponse> publicKeyCredential = objectConverter.getJsonConverter().readValue(httpServletRequest.getInputStream(), credentialTypeRef);
        serverPublicKeyCredentialValidator.validate(publicKeyCredential);

        ServerAuthenticatorAssertionResponse assertionResponse = publicKeyCredential.getResponse();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId() == null ? null : Base64UrlUtil.decode(publicKeyCredential.getRawId()),
                assertionResponse.getUserHandle() == null ? null : Base64UrlUtil.decode(assertionResponse.getUserHandle()),
                assertionResponse.getAuthenticatorData() == null ? null : Base64UrlUtil.decode(assertionResponse.getAuthenticatorData()),
                assertionResponse.getClientDataJSON() == null ? null : Base64UrlUtil.decode(assertionResponse.getClientDataJSON()),
                publicKeyCredential.getClientExtensionResults(),
                assertionResponse.getSignature() == null ? null : Base64UrlUtil.decode(assertionResponse.getSignature())
        );

        Origin origin = new Origin(httpServletRequest.getRequestURL().toString());
        Challenge challenge = new DefaultChallenge((byte[]) session.getAttribute("challenge"));
        ServerProperty serverProperty = new ServerProperty(origin, origin.getHost(), challenge, null);
        CredentialRecord credentialRecord = credentialRecordService.getByCredentialId(Base64UrlUtil.decode(publicKeyCredential.getRawId()));
        UserVerificationRequirement userVerificationRequirement = UserVerificationRequirement.create((String) session.getAttribute("uv"));

        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                userVerificationRequirement == UserVerificationRequirement.REQUIRED,
                false
        );

        try{
            webAuthnAuthenticationAsyncManager.verify(authenticationRequest, authenticationParameters).toCompletableFuture().get();
        }
        catch (Exception e){
            return objectConverter.getJsonConverter().writeValueAsString(new ErrorResponse(e.getMessage()));
        }

        return objectConverter.getJsonConverter().writeValueAsString(new AssertionResultSuccessResponse());
    }
}
