package org.dependencytrack.tasks;

import alpine.event.framework.Event;
import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.model.CsafDocumentEntity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.dependencytrack.datasource.vuln.csaf.CycloneDxPropertyNames.*;

/**
 * An abstract task that mirrors advisory-based vulnerability data sources. These data sources can
 * contain multiple vulnerabilities per advisory, and the advisory itself is a first-class entity.
 *
 * @since 5.7.0
 */
public abstract class AbstractAdvisoryMirrorTask extends AbstractVulnDataSourceMirrorTask {

    AbstractAdvisoryMirrorTask(PluginManager pluginManager, Class<? extends Event> eventClass, String vulnDataSourceExtensionName, Vulnerability.Source source) {
        super(pluginManager, eventClass, vulnDataSourceExtensionName, source);
    }

    @Override
    protected void processBatch(final VulnDataSource dataSource, final Collection<Bom> bovs) {
        logger.debug("Processing batch of {} BOVs", bovs.size());

        final var advisories = new ArrayList<CsafDocumentEntity>();
        final var vulns = new ArrayList<Vulnerability>(bovs.size());
        final var vsListByVulnId = new HashMap<String, List<VulnerableSoftware>>(bovs.size());

        for (final Bom bov : bovs) {
            final var advisory = new CsafDocumentEntity();
            advisory.setName(extractProperty(bov, PROPERTY_ADVISORY_TITLE, String.class));
            advisory.setLastFetched(extractProperty(bov, PROPERTY_ADVISORY_UPDATED, Instant.class));
            advisory.setContent(extractProperty(bov, PROPERTY_ADVISORY_JSON, String.class));
            advisory.setTrackingID(extractProperty(bov, PROPERTY_ADVISORY_NAME, String.class));
            advisory.setTrackingVersion(extractProperty(bov, PROPERTY_ADVISORY_VERSION, String.class));
            advisory.setPublisherNamespace(extractProperty(bov, PROPERTY_ADVISORY_PUBLISHER_NAMESPACE, String.class));
            advisory.setUrl(extractProperty(bov, PROPERTY_ADVISORY_URL, String.class));

            advisories.add(advisory);

            for (final var v : bov.getVulnerabilitiesList()) {
                final Vulnerability vuln = BovModelConverter.convert(bov, v, true);
                final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

                vulns.add(vuln);
                vsListByVulnId.put(vuln.getVulnId(), vsList);
            }
        }

        try (final var qm = new QueryManager()) {
            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");

            qm.runInTransaction(() -> {
                for (final CsafDocumentEntity advisory : advisories) {
                    logger.debug("Synchronizing advisory {}", advisory.getName());
                    qm.synchronizeCsafDocument(advisory);
                }

                for (final Vulnerability vuln : vulns) {
                    logger.debug("Synchronizing vulnerability {}", vuln.getVulnId());
                    final Vulnerability persistentVuln = qm.synchronizeVulnerability(vuln, false);
                    final List<VulnerableSoftware> vsList = vsListByVulnId.get(persistentVuln.getVulnId());
                    qm.synchronizeVulnerableSoftware(persistentVuln, vsList, this.source);
                }
            });
        }

        for (final Bom bov : bovs) {
            dataSource.markProcessed(bov);
        }
    }

}
