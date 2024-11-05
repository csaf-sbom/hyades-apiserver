package org.dependencytrack.persistence;

import java.util.List;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.CsafEntity;
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
            query.setOrdering("name asc");
        }
        /*if (filter != null) {//TODO enable filtering
            query.setFilter("identifier.toLowerCase().matches(:identifier)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }*/
        return execute(query);
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

     /**
     * Creates a new CSAF Entity.
     *
     * @param type                     the type of repository
     * @param identifier               a unique (to the type) identifier for the repo
     * @param url                      the URL to the repository
     * @param enabled                  if the repo is enabled or not
     * @param internal                 if the repo is internal or not
     * @param isAuthenticationRequired if the repository needs authentication or not
     * @param username                 the username to access the (authenticated) repository with
     * @param password                 the password to access the (authenticated) repository with
     * @return the created Repository
     */
    public Repository createRepository(RepositoryType type, String identifier, String url, boolean enabled, boolean internal, boolean isAuthenticationRequired, String username, String password) {
        if (repositoryExist(type, identifier)) {
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
        }
        final Repository repo = new Repository();
        repo.setType(type);
        repo.setIdentifier(identifier);
        repo.setUrl(url);
        repo.setResolutionOrder(order + 1);
        repo.setEnabled(enabled);
        repo.setInternal(internal);
        repo.setAuthenticationRequired(isAuthenticationRequired);
        if (Boolean.TRUE.equals(isAuthenticationRequired) && (username != null || password != null)) {
            repo.setUsername(StringUtils.trimToNull(username));
            try {
                if (password != null) {
                    repo.setPassword(DataEncryption.encryptAsString(password));
                }
            } catch (Exception e) {
                LOGGER.error("An error occurred while saving password in encrypted state", e);
            }
        }
        return persist(repo);
    }
}
