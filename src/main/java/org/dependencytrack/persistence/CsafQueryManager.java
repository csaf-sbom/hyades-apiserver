package org.dependencytrack.persistence;

import java.util.List;
import java.util.UUID;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.CsafEntity;
import org.dependencytrack.model.CsafEntityType;
import org.dependencytrack.model.Repository;

import alpine.common.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import alpine.security.crypto.DataEncryption;

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
     * Returns a list of all CSAF entities.
     *
     * @return a List of CSAF entities
     */
    public PaginatedResult getCsafEntities() {
        final Query<CsafEntity> query = pm.newQuery(CsafEntity.class);
        if (orderBy == null) {
            query.setOrdering("csafEntryId desc");
        }
        /*if (filter != null) {//TODO enable filtering
            query.setFilter("identifier.toLowerCase().matches(:identifier)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }*/

        return execute(query);
    }

    @Override
    public PaginatedResult getCsafDocuments() {
        final Query<CsafEntity> query = pm.newQuery(CsafEntity.class);
        if(orderBy == null) query.setOrdering("csafEntryId desc");

        query.filter("entityType == :entityType");
        return execute(query, CsafEntityType.DOCUMENT);
    }

    /**
     * Returns a list of all CSAF entities
     * This method is designed NOT to provide paginated results.
     * 
     * @return a List of <CsafEntity>
     */
    public List<CsafEntity> getAllCsafEntities() {
        final Query<CsafEntity> query = pm.newQuery(CsafEntity.class);
        //query.setOrdering("type asc, identifier asc")
        return query.executeList();
    }

    /**
     * Creates a new CSAF Entity
     * @param name Name of the CSAF entity
     * @param url URL of the configured source
     * @param enabled True, if source should be used for mirroring
     * @return the created CSAF entity
     */
    public CsafEntity createCsafEntity(String name, String url, boolean enabled) {
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
        final CsafEntity csaf = new CsafEntity();
        csaf.setName(name);
        csaf.setUrl(url);
        csaf.setEnabled(enabled);


        return persist(csaf);
    }

    @Override
    public CsafEntity createCsafFileEntity(String name, byte[] contents, boolean enabled) {
        final var csaf = new CsafEntity();
        csaf.setEntityType(CsafEntityType.DOCUMENT);
        csaf.setName(name);
        csaf.setContent(contents);
        csaf.setEnabled(enabled);
        return persist(csaf);
    }

    /**
     * Updates an existing CSAF entity.
     *
     * @oaram csafEntryId ID of the CSAF source
     * @param name Name of the CSAF entity
     * @param url URL of the configured source
     * @param enabled True, if source should be used for mirroring
     * @return the created CSAF entity
     */
    public CsafEntity updateCsafEntity(long csafEntryId, String name, String url, boolean enabled) {
        LOGGER.debug("Updating within CsafQueryManager "+csafEntryId);
        final CsafEntity csafEntity = getObjectById(CsafEntity.class, csafEntryId);
        csafEntity.setCsafEntryId(csafEntryId);
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
