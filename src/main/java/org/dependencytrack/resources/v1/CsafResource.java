/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import static alpine.event.framework.Event.isEventBeingProcessed;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.StandardCopyOption;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.VulnerabilityPolicyFetchEvent;
import org.dependencytrack.model.CsafEntity;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyProvider;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyProviderFactory;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.resources.v1.vo.BomUploadResponse;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.persistence.PaginatedResult;
import alpine.security.crypto.DataEncryption;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * Resource for vulnerability policies.
 */
@Path("/v1/csaf")
@Tag(name = "csaf")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class CsafResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(CsafResource.class);
    /*
     * @GET
     * 
     * @Produces(MediaType.APPLICATION_JSON)
     * 
     * @Operation(
     * summary = "Returns a list of configured CSAF resources",
     * description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>"
     * )
     * 
     * @PaginatedApi
     * 
     * @ApiResponses(value = {
     * 
     * @ApiResponse(
     * responseCode = "200",
     * description = "A list of all configured CSAF resources",
     * headers = @Header(name = TOTAL_COUNT_HEADER, schema = @Schema(format =
     * "integer"), description = "The total number of configured CSAF resources"),
     * content = @Content(array = @ArraySchema(schema = @Schema(implementation =
     * CsafEntity.class)))
     * ),
     * 
     * @ApiResponse(responseCode = "401", description = "Unauthorized")
     * })
     * 
     * @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT})
     * public Response getCsafConfiguredResources() {
     * VulnerabilityPolicyProviderFactory instance =
     * VulnerabilityPolicyProviderFactory.getInstance();
     * VulnerabilityPolicyProvider vulnerabilityPolicyProvider =
     * instance.policyProviderImpl();
     * final PaginatedResult result =
     * vulnerabilityPolicyProvider.getAllVulnerabilityPolicies(getAlpineRequest());
     * 
     * return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER,
     * result.getTotal()).build();
     * }
     * 
     * @POST
     * 
     * @Path("/bundle/sync")
     * 
     * @Produces(MediaType.APPLICATION_JSON)
     * 
     * @Operation(
     * summary =
     * "Triggers policy bundle synchronization. Returns a workflow token if trigger succeeded."
     * ,
     * // responseContainer = "Map",
     * description =
     * "<p>Requires permission <strong>POLICY_MANAGEMENT</strong> or <strong>POLICY_MANAGEMENT_UPDATE</strong></p>"
     * )
     * 
     * @ApiResponses(value = {
     * 
     * @ApiResponse(
     * responseCode = "200",
     * description = "Token to be used for checking synchronization progress",
     * content = @Content(schema = @Schema(implementation =
     * BomUploadResponse.class))
     * ),
     * 
     * @ApiResponse(responseCode = "202", description = "Accepted"),
     * 
     * @ApiResponse(responseCode = "401", description = "Unauthorized"),
     * 
     * @ApiResponse(responseCode = "409", description = "Conflict")
     * })
     * 
     * @PermissionRequired({Permissions.Constants.POLICY_MANAGEMENT,
     * Permissions.Constants.POLICY_MANAGEMENT_UPDATE})
     * public Response triggerVulnerabilityPolicyBundleSync() {
     * if (!Config.getInstance().getPropertyAsBoolean(ConfigKey.
     * VULNERABILITY_POLICY_ANALYSIS_ENABLED)) {
     * return Response
     * .status(Response.Status.BAD_REQUEST)
     * .entity("The vulnerability policy feature has not been enabled by the instance administrator"
     * )
     * .build();
     * }
     * 
     * try (final var qm = new QueryManager()) {
     * // If a workflow instance exists already, prevent concurrent modifications
     * // by using "SELECT ... FOR UPDATE" to lock the record for the transaction.
     * qm.getPersistenceManager().currentTransaction().setSerializeRead(true);
     * 
     * final UUID token = VulnerabilityPolicyFetchEvent.CHAIN_IDENTIFIER;
     * final Response response = qm.callInTransaction(() -> {
     * WorkflowState workflowState = qm.getWorkflowStateByTokenAndStep(token,
     * WorkflowStep.POLICY_BUNDLE_SYNC);
     * if (workflowState != null) {
     * if (isEventBeingProcessed(token) || !workflowState.getStatus().isTerminal())
     * {
     * return Response
     * .status(Response.Status.CONFLICT)
     * .entity(Map.of("message", "Bundle synchronization is already in progress"))
     * .build();
     * }
     * 
     * workflowState.setStatus(WorkflowStatus.PENDING);
     * workflowState.setStartedAt(null);
     * workflowState.setUpdatedAt(new Date());
     * } else {
     * workflowState = new WorkflowState();
     * workflowState.setStep(WorkflowStep.POLICY_BUNDLE_SYNC);
     * workflowState.setStatus(WorkflowStatus.PENDING);
     * workflowState.setToken(token);
     * workflowState.setUpdatedAt(new Date());
     * qm.getPersistenceManager().makePersistent(workflowState);
     * }
     * 
     * return Response.accepted(Map.of("token", token)).build();
     * });
     * 
     * LOGGER.info("Policy bundle synchronization triggered by %s".formatted(
     * getPrincipal().getName()));
     * Event.dispatch(new VulnerabilityPolicyFetchEvent());
     * return response;
     * } catch (RuntimeException e) {
     * if (ExceptionUtils.getRootCause(e) instanceof final PSQLException pe
     * && pe.getSQLState().equals(PSQLState.UNIQUE_VIOLATION.getState())) {
     * return Response
     * .status(Response.Status.CONFLICT)
     * .entity(Map.of("message", "Bundle synchronization is already in progress"))
     * .build();
     * }
     * 
     * LOGGER.error("Failed to trigger vulnerability policy bundle sync", e);
     * return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
     * }
     * }
     */

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of CSAF entities", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of CSAF entities", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of CSAF entities", schema = @Schema(type = "integer")), content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafEntity.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({ Permissions.Constants.CSAF_MANAGEMENT })
    public Response getCsafEntities() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getCsafEntities();
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Creates a new CSAF resource", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "The created CSAF resource", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A repository with the specified identifier already exists")
    })
    @PermissionRequired({ Permissions.Constants.CSAF_MANAGEMENT })
    public Response createCsafEntity(CsafEntity jsonEntity) {
        // final Validator validator = super.getValidator();
        // failOnValidationError(
        // validator.validateProperty(jsonRepository, "identifier"),
        // validator.validateProperty(jsonRepository, "url")
        // );
        // //TODO: When the UI changes are updated then this should be a validation
        // check as part of line 160
        // if (jsonRepository.isAuthenticationRequired() == null) {
        // jsonRepository.setAuthenticationRequired(false);
        // }
        try (QueryManager qm = new QueryManager()) {
            // qm.reposityEx
            // final boolean exists = qm.repositoryExist(jsonRepository.getType(),
            // StringUtils.trimToNull(jsonRepository.getIdentifier()));
            // if (!exists) {
            /*
             * final Repository repository = qm.createRepository(
             * jsonRepository.getType(),
             * StringUtils.trimToNull(jsonRepository.getIdentifier()),
             * StringUtils.trimToNull(jsonRepository.getUrl()),
             * jsonRepository.isEnabled(),
             * jsonRepository.isInternal(),
             * jsonRepository.isAuthenticationRequired(),
             * jsonRepository.getUsername(), jsonRepository.getPassword());
             * 
             * return Response.status(Response.Status.CREATED).entity(repository).build();
             */
            // } else {
            // return Response.status(Response.Status.CONFLICT).entity("A repository with
            // the specified identifier already exists.").build();
            // }
            final CsafEntity csafEntity = qm.createCsafEntity(jsonEntity.getName(), jsonEntity.getUrl(),
                    jsonEntity.isEnabled());
            return Response.status(Response.Status.CREATED).entity(csafEntity).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Updates a CSAF entity", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated CSAF entity", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the repository could not be found")
    })
    @PermissionRequired({ Permissions.Constants.CSAF_MANAGEMENT }) // TODO create update only permission
    public Response updateCsafEntity(CsafEntity jsonEntity) {
        /*
         * final Validator validator = super.getValidator(); // TODO validate
         * failOnValidationError(validator.validateProperty(jsonRepository,
         * "identifier"),
         * validator.validateProperty(jsonRepository, "url")
         * );
         * //TODO: When the UI changes are updated then this should be a validation
         * check as part of line 201
         * if (jsonRepository.isAuthenticationRequired() == null) {
         * jsonRepository.setAuthenticationRequired(false);
         * }
         */
        try (QueryManager qm = new QueryManager()) {
            CsafEntity csafEntity = qm.getObjectById(CsafEntity.class, jsonEntity.getCsafEntryId());
            if (csafEntity != null) {
                final String url = StringUtils.trimToNull(jsonEntity.getUrl());
                try {
                    /*
                     * // The password is not passed to the front-end, so it should only be
                     * overwritten if it is not null.
                     * final String updatedPassword = jsonRepository.getPassword() != null &&
                     * !jsonRepository.getPassword().equals(ENCRYPTED_PLACEHOLDER)
                     * ? DataEncryption.encryptAsString(jsonRepository.getPassword())
                     * : repository.getPassword();
                     */
                    csafEntity = qm.updateCsafEntity(jsonEntity.getCsafEntryId(), jsonEntity.getName(),
                            jsonEntity.getUrl(), jsonEntity.isEnabled());

                    return Response.ok(csafEntity).build();
                } catch (Exception e) {
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                            .entity("The specified CSAF source could not be updated").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The csafEntryId of the source could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/{csafEntryId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Deletes a CSAF source", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "CSAF source removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The entry ID of the CSAF source could not be found")
    })
    @PermissionRequired({ Permissions.Constants.CSAF_MANAGEMENT }) // TODO OR delete only permission
    public Response deleteCsafEntity(
            @Parameter(description = "The csafEntryId of the CSAF source to delete", schema = @Schema(type = "string", format = "long"), required = true) @PathParam("csafEntryId") String csafEntryId) {
        try (QueryManager qm = new QueryManager()) {

            final CsafEntity csafEntity = qm.getObjectById(CsafEntity.class, csafEntryId);
            if (csafEntity != null) {
                qm.delete(csafEntity);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The csafEntryId of the CSAF source could not be found.").build();
            }
        }
    }

    @GET
    @Path("/discoveries/")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of discovered CSAF sources", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of discovered CSAF sources", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of discovered CSAF sources", schema = @Schema(type = "integer")), content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafEntity.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({ Permissions.Constants.CSAF_MANAGEMENT })
    public Response getDiscoveredCsafSources() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            var results = qm.getCsafEntities();
            final PaginatedResult result = results;
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/documents/")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of CSAF documents", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of CSAF documents", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of CSAF documents", schema = @Schema(type = "integer")), content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafEntity.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({ Permissions.Constants.CSAF_MANAGEMENT })
    public Response getCsafDocuments() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            var results = qm.getCsafEntities();
            final PaginatedResult result = results;
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @PUT
    @Path("/documents/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Upload a new CSAF document", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "The created CSAF document", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A repository with the specified identifier already exists")
    })
    @PermissionRequired({ Permissions.Constants.CSAF_MANAGEMENT })
    public Response uploadCsafDocument(CsafEntity jsonEntity) {
        // final Validator validator = super.getValidator();
        // failOnValidationError(
        // validator.validateProperty(jsonRepository, "identifier"),
        // validator.validateProperty(jsonRepository, "url")
        // );
        // //TODO: When the UI changes are updated then this should be a validation
        // check as part of line 160
        // if (jsonRepository.isAuthenticationRequired() == null) {
        // jsonRepository.setAuthenticationRequired(false);
        // }
        try (QueryManager qm = new QueryManager()) {
            // qm.reposityEx
            // final boolean exists = qm.repositoryExist(jsonRepository.getType(),
            // StringUtils.trimToNull(jsonRepository.getIdentifier()));
            // if (!exists) {
            /*
             * final Repository repository = qm.createRepository(
             * jsonRepository.getType(),
             * StringUtils.trimToNull(jsonRepository.getIdentifier()),
             * StringUtils.trimToNull(jsonRepository.getUrl()),
             * jsonRepository.isEnabled(),
             * jsonRepository.isInternal(),
             * jsonRepository.isAuthenticationRequired(),
             * jsonRepository.getUsername(), jsonRepository.getPassword());
             * 
             * return Response.status(Response.Status.CREATED).entity(repository).build();
             */
            // } else {
            // return Response.status(Response.Status.CONFLICT).entity("A repository with
            // the specified identifier already exists.").build();
            // }
            // final CsafEntity csafEntity = qm.createCsafEntity(jsonEntity.getName(),
            // jsonEntity.getUrl(), jsonEntity.isEnabled());
            // return Response.status(Response.Status.CREATED).entity(csafEntity).build();
            return Response.status(Response.Status.NOT_IMPLEMENTED).build();
        }
    }

    @POST
    @Path("/fileupload")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response uploadFile(
        @FormDataParam("file") InputStream uploadStream,
        @FormDataParam("file") FormDataContentDisposition fileDetail
    ) {
        System.out.println(fileDetail);
        try {
            // Save the file to the server
            var outputStream = new ByteArrayOutputStream();
            uploadStream.transferTo(outputStream);

            var content = new String(outputStream.toByteArray());

            System.out.println(content);

            return Response.ok("File uploaded successfully: "+fileDetail.getFileName()).build();
        } catch (IOException e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                           .entity("File upload failed").build();
        }
    }

    @POST
    @Path("/documents/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Updates a CSAF document", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated CSAF document", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the repository could not be found")
    })
    @PermissionRequired({ Permissions.Constants.CSAF_MANAGEMENT }) // TODO create update only permission
    public Response updateCsafDocument(CsafEntity jsonEntity) {
        /*
         * final Validator validator = super.getValidator(); // TODO validate
         * failOnValidationError(validator.validateProperty(jsonRepository,
         * "identifier"),
         * validator.validateProperty(jsonRepository, "url")
         * );
         * //TODO: When the UI changes are updated then this should be a validation
         * check as part of line 201
         * if (jsonRepository.isAuthenticationRequired() == null) {
         * jsonRepository.setAuthenticationRequired(false);
         * }
         */
        /*
         * try (QueryManager qm = new QueryManager()) {
         * CsafEntity csafEntity = qm.getObjectById(CsafEntity.class,
         * jsonEntity.getCsafEntryId());
         * if (csafEntity != null) {
         * final String url = StringUtils.trimToNull(jsonEntity.getUrl());
         * try {
         * /// The password is not passed to the front-end, so it should only be
         * overwritten if it is not null.
         * final String updatedPassword = jsonRepository.getPassword() != null &&
         * !jsonRepository.getPassword().equals(ENCRYPTED_PLACEHOLDER)
         * ? DataEncryption.encryptAsString(jsonRepository.getPassword())
         * : repository.getPassword();
         * /
         * csafEntity = qm.updateCsafEntity(jsonEntity.getCsafEntryId(),
         * jsonEntity.getName(), jsonEntity.getUrl(), jsonEntity.isEnabled());
         * 
         * return Response.ok(csafEntity).build();
         * } catch (Exception e) {
         * return Response.status(Response.Status.INTERNAL_SERVER_ERROR).
         * entity("The specified CSAF source could not be updated").build();
         * }
         * } else {
         * return Response.status(Response.Status.NOT_FOUND).
         * entity("The csafEntryId of the source could not be found.").build();
         * }
         * }
         */
        return Response.status(Response.Status.NOT_IMPLEMENTED).build();
    }

    @DELETE
    @Path("/documents/{csafDocumentId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Deletes a CSAF source", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "CSAF source removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The entry ID of the CSAF source could not be found")
    })
    @PermissionRequired({ Permissions.Constants.CSAF_MANAGEMENT }) // TODO OR delete only permission
    public Response deleteCsafDocument(
            @Parameter(description = "The csafEntryId of the CSAF source to delete", schema = @Schema(type = "string", format = "long"), required = true) @PathParam("csafEntryId") String csafEntryId) {
        /*
         * try (QueryManager qm = new QueryManager()) {
         * 
         * 
         * final CsafEntity csafEntity = qm.getObjectById(CsafEntity.class,
         * csafEntryId);
         * if (csafEntity != null) {
         * qm.delete(csafEntity);
         * return Response.status(Response.Status.NO_CONTENT).build();
         * } else {
         * return Response.status(Response.Status.NOT_FOUND).
         * entity("The csafEntryId of the CSAF source could not be found.").build();
         * }
         * }
         */
        return Response.status(Response.Status.NOT_IMPLEMENTED).build();
    }
}
