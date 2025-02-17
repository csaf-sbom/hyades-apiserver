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
package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.CsafSourceEntity;
import org.dependencytrack.model.CsafDocumentEntity;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

public class CsafQueryManager extends QueryManager implements IQueryManager {
    private static final Logger LOGGER = Logger.getLogger(CsafQueryManager.class);
    /**
     * Constructs a new CsafQueryManager.
     *
     * @param pm a PersistenceManager object
     */
    CsafQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new CsafQueryManager.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    CsafQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }


    /**
     *
     * @param aggregators true if aggregators should be fetched, false if providers are to be shown
     * @return list of csaf sources
     */
    @Override
    public PaginatedResult getCsafSources(boolean aggregators) {
        final Query<CsafSourceEntity> query = pm.newQuery(CsafSourceEntity.class);
        query.filter("aggregator == :aggregator");
        if(orderBy == null) query.setOrdering("entryId desc");

        return execute(query, aggregators);
    }

    /**
     * Get discoveries, either aggregators or providers
     * @return
     */
    @Override
    public PaginatedResult getCsafSourcesDiscoveries() {
        final Query<CsafSourceEntity> query = pm.newQuery(CsafSourceEntity.class);
        query.filter("discovery == :discoveries");
        if(orderBy == null) query.setOrdering("entryId desc");

        return execute(query, true);
    }

    /**
     * Creates a new CSAF Entity
     * @param name Name of the CSAF entity
     * @param url URL of the configured source
     * @param enabled True, if source should be used for mirroring
     * @return the created CSAF entity
     */
    @Override
    public CsafSourceEntity createCsafSource(String name, String url, boolean enabled, boolean aggregator) {
        /*if (repositoryExist(type, identifier)) { // TODO check existing
            return null;
        }
        int order = 0;
        final List<Repository> existingRepos = getAllRepositoriesOrdered(type);
        if (existingRepos != null) {
            for (final Repository existing : existingRepos) {
                if (existing.getResolutionOrder() > order) {
                    order = existing.getResolutionOrder();
                }
            }
        }*/
        final CsafSourceEntity csaf = new CsafSourceEntity();
        csaf.setName(name);
        csaf.setUrl(url);
        csaf.setEnabled(enabled);
        csaf.setAggregator(aggregator);

        return persist(csaf);
    }

    @Override
    public CsafSourceEntity createCsafSourceFromFile(String name, String contents, boolean enabled, boolean aggregator) {
        final var csaf = new CsafSourceEntity();
        csaf.setName(name);
        csaf.setContent(contents);
        csaf.setEnabled(enabled);
        csaf.setAggregator(aggregator);
        return persist(csaf);
    }

    /**
     * Updates an existing CSAF entity.
     *
     * @param csafEntryId ID of the CSAF source
     * @param name Name of the CSAF entity
     * @param url URL of the configured source
     * @param enabled True, if source should be used for mirroring
     * @return the created CSAF entity
     */
    @Override
    public CsafSourceEntity updateCsafSource(long csafEntryId, String name, String url, boolean enabled) {
        LOGGER.debug("Updating within CsafQueryManager "+csafEntryId);
        final CsafSourceEntity csafEntity = getObjectById(CsafSourceEntity.class, csafEntryId);
        csafEntity.setName(name);
        csafEntity.setUrl(url);
        /*repository.setInternal(internal);
        repository.setAuthenticationRequired(authenticationRequired);
        if (!authenticationRequired) {
            repository.setUsername(null);
            repository.setPassword(null);
        } else {
            repository.setUsername(username);
            repository.setPassword(password);
        }*/

        csafEntity.setEnabled(enabled);
        return persist(csafEntity);
    }

    @Override
    public PaginatedResult getCsafDocuments() {
        final Query<CsafDocumentEntity> query = pm.newQuery(CsafDocumentEntity.class);
        if(orderBy == null) query.setOrdering("entryId desc");

        return execute(query);
    }


    /**
     * Creates a new CSAF Entity
     * @param name Name of the CSAF entity
     * @param url URL of the configured source
     * @param enabled True, if source should be used for mirroring
     * @return the created CSAF entity
     */
    @Override
    public CsafDocumentEntity createCsafDocument(String name, String url, boolean enabled) {
        /*if (repositoryExist(type, identifier)) { // TODO check existing
            return null;
        }
        int order = 0;
        final List<Repository> existingRepos = getAllRepositoriesOrdered(type);
        if (existingRepos != null) {
            for (final Repository existing : existingRepos) {
                if (existing.getResolutionOrder() > order) {
                    order = existing.getResolutionOrder();
                }
            }
        }*/
        final CsafDocumentEntity csaf = new CsafDocumentEntity();
        csaf.setName(name);
        csaf.setUrl(url);
        csaf.setEnabled(enabled);

        return persist(csaf);
    }

    @Override
    public CsafDocumentEntity createCsafDocumentFromFile(String name, String contents, boolean enabled) {
        final var csaf = new CsafDocumentEntity();
        csaf.setName(name);
        csaf.setContent(contents);
        csaf.setEnabled(enabled);
        return persist(csaf);
    }

    /**
     * Updates an existing CSAF entity.
     *
     * @param csafEntryId ID of the CSAF source
     * @param name Name of the CSAF entity
     * @param url URL of the configured source
     * @param enabled True, if source should be used for mirroring
     * @return the created CSAF entity
     */
    @Override
    public CsafDocumentEntity updateCsafDocument(long csafEntryId, String name, String url, boolean enabled) {
        LOGGER.debug("Updating within CsafQueryManager "+csafEntryId);
        final CsafDocumentEntity csafEntity = getObjectById(CsafDocumentEntity.class, csafEntryId);
        csafEntity.setName(name);
        csafEntity.setUrl(url);
        /*repository.setInternal(internal);
        repository.setAuthenticationRequired(authenticationRequired);
        if (!authenticationRequired) {
            repository.setUsername(null);
            repository.setPassword(null);
        } else {
            repository.setUsername(username);
            repository.setPassword(password);
        }*/

        csafEntity.setEnabled(enabled);
        return persist(csafEntity);
    }
}
