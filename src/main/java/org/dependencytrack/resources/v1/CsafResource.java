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

import alpine.common.logging.Logger;
import alpine.persistence.PaginatedResult;
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
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.CsafEntity;
import org.dependencytrack.model.CsafEntityType;
import org.dependencytrack.model.Repository;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

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

    @GET
    @Path("/aggregators/")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of CSAF aggregators", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of CSAF entities", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of CSAF entities", schema = @Schema(type = "integer")), content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafEntity.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT})
    public Response getCsafAggregators() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getCsafEntitiesByType(CsafEntityType.AGGREGATOR);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @PUT
    @Path("/aggregators/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Creates a new CSAF aggregator", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "The created CSAF aggregator", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "An aggregator with the specified identifier already exists")
    })
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT})
    public Response createCsafAggregator(CsafEntity jsonEntity) {
        try (QueryManager qm = new QueryManager()) {
            final CsafEntity csafEntity = qm.createCsafEntity(jsonEntity.getName(), jsonEntity.getUrl(),
                    jsonEntity.isEnabled());
            return Response.status(Response.Status.CREATED).entity(csafEntity).build();
        } catch (Exception e) {
            return Response.status(Response.Status.CONFLICT).build();
        }
    }

    @POST
    @Path("/aggregators/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Updates a CSAF aggregator", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated CSAF aggregator", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The csafEntryId of the aggregator could not be found")
    })
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT}) // TODO create update only permission
    public Response updateCsafAggregator(CsafEntity jsonEntity) {
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
    @Path("/aggregators/{csafEntryId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Deletes a CSAF aggregator", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "CSAF source removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The entry ID of the CSAF source could not be found")
    })
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT}) // TODO OR delete only permission
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
    @Path("/providers/")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of CSAF providers", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of CSAF providers", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of CSAF entities", schema = @Schema(type = "integer")), content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafEntity.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT})
    public Response getCsafProviders() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getCsafEntitiesByType(CsafEntityType.PROVIDER);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @PUT
    @Path("/providers/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Creates a new CSAF provider", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "The created CSAF provider", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "An provider with the specified identifier already exists")
    })
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT})
    public Response createCsafProvider(CsafEntity jsonEntity) {
        try (QueryManager qm = new QueryManager()) {
            final CsafEntity csafEntity = qm.createCsafEntity(jsonEntity.getName(), jsonEntity.getUrl(),
                    jsonEntity.isEnabled());
            return Response.status(Response.Status.CREATED).entity(csafEntity).build();
        } catch (Exception e) {
            return Response.status(Response.Status.CONFLICT).build();
        }
    }

    @POST
    @Path("/providers/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Updates a CSAF provider", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated CSAF provider", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The csafEntityId of the provider could not be found")
    })
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT}) // TODO create update only permission
    public Response updateCsafProvider(CsafEntity jsonEntity) {
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

    @GET
    @Path("/discoveries/")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of discovered CSAF sources", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "A list of discovered CSAF sources", headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of discovered CSAF sources", schema = @Schema(type = "integer")), content = @Content(array = @ArraySchema(schema = @Schema(implementation = CsafEntity.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT})
    public Response getDiscoveredCsafSources() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            var results = qm.getCsafEntitiesByType(CsafEntityType.DISCOVERED_AGGREGATOR);

            // TODO Add default suggestions
            var bsiWid = new CsafEntity(CsafEntityType.DISCOVERED_AGGREGATOR, "BSI WID (hardcoded sample)", "https://wid.cert-bund.de/");
            results.getObjects().add(bsiWid);
            results.setTotal(results.getObjects().size());

            return Response.ok(results.getObjects()).header(TOTAL_COUNT_HEADER, results.getTotal()).build();
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
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT})
    public Response getCsafDocuments() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            var results = qm.getCsafEntitiesByType(CsafEntityType.DOCUMENT);
            return Response.ok(results.getObjects()).header(TOTAL_COUNT_HEADER, results.getTotal()).build();
        }
    }

    @PUT
    @Path("/documents/")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.TEXT_PLAIN)
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT})
    @Operation(summary = "Upload a new CSAF document", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The created CSAF document", content = @Content(schema = @Schema(implementation = Repository.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A repository with the specified identifier already exists")
    })
    public Response uploadCsafDocument(
            @FormDataParam("file") InputStream uploadStream,
            @FormDataParam("file") FormDataContentDisposition fileDetail
    ) {
        System.out.println(fileDetail);
        try (var qm = new QueryManager();
             var uploadBuffer = new ByteArrayOutputStream()) {

            uploadStream.transferTo(uploadBuffer);

            qm.createCsafFileEntity(fileDetail.getFileName(), uploadBuffer.toByteArray()
                    , true);
            return Response.ok("File uploaded successfully: " + fileDetail.getFileName()).build();
        } catch (IOException e) {
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
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT}) // TODO create update only permission
    public Response updateCsafDocument(CsafEntity jsonEntity) {

        try (QueryManager qm = new QueryManager()) {
            CsafEntity csafEntity = qm.getObjectById(CsafEntity.class,
                    jsonEntity.getCsafEntryId());
            if (csafEntity != null) {
                final String url = StringUtils.trimToNull(jsonEntity.getUrl());
                try {

                    csafEntity = qm.updateCsafEntity(jsonEntity.getCsafEntryId(),
                            jsonEntity.getName(), jsonEntity.getUrl(), jsonEntity.isEnabled());

                    return Response.ok(csafEntity).build();
                } catch (Exception e) {
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).
                            entity("The specified CSAF source could not be updated").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).
                        entity("The csafEntryId of the source could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/documents/{csafEntryId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Deletes a CSAF source", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "CSAF source removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The entry ID of the CSAF source could not be found")
    })
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT}) // TODO OR delete only permission
    public Response deleteCsafDocument(
            @Parameter(description = "The csafEntryId of the CSAF source to delete", schema = @Schema(type = "string", format = "long"), required = true) @PathParam("csafEntryId") String csafEntryId) {

        try (QueryManager qm = new QueryManager()) {
            final CsafEntity csafEntity = qm.getObjectById(CsafEntity.class,
                    csafEntryId);
            if (csafEntity != null) {
                qm.delete(csafEntity);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).
                        entity("The csafEntryId of the CSAF source could not be found.").build();
            }
        }
    }

    @GET
    @Path("/documents/{csafEntryId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    @Operation(summary = "Returns the contents of a CSAF document", description = "<p>Requires permission <strong>CSAF_MANAGEMENT</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The content of a document"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.CSAF_MANAGEMENT})
    public Response getCsafDocumentContents(@Parameter(description = "The csafEntryId of the CSAF document to view", schema = @Schema(type = "string", format = "long"), required = true) @PathParam("csafEntryId") String csafEntryId) {
        try (QueryManager qm = new QueryManager()) {
            final var csafEntity = qm.getObjectById(CsafEntity.class, csafEntryId);

            if(csafEntity == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The requested CSAF document could not be found.").build();
            } else {
                return Response.ok(new String(csafEntity.getContent())).build();
            }
        }
    }
}
