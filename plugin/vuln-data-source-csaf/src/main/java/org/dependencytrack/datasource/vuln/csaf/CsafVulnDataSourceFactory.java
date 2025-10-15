package org.dependencytrack.datasource.vuln.csaf;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.SequencedCollection;

import static org.dependencytrack.datasource.vuln.csaf.CsafVulnDataSourceConfigs.CONFIG_ENABLED;
import static org.dependencytrack.datasource.vuln.csaf.CsafVulnDataSourceConfigs.CONFIG_SOURCES;

public class CsafVulnDataSourceFactory implements VulnDataSourceFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(CsafVulnDataSourceFactory.class);

    private ConfigRegistry configRegistry;
    private ObjectMapper objectMapper;

    @Override
    public String extensionName() {
        return "csaf";
    }

    @Override
    public Class<? extends VulnDataSource> extensionClass() {
        return CsafVulnDataSource.class;
    }

    @Override
    public int priority() {
        return 0;
    }

    @Override
    public SequencedCollection<RuntimeConfigDefinition<?>> runtimeConfigs() {
        return List.of(
                CONFIG_ENABLED,
                CONFIG_SOURCES);
    }

    @Override
    public void init(final ExtensionContext ctx) {
        this.configRegistry = ctx.configRegistry();
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @Override
    public boolean isDataSourceEnabled() {
        return this.configRegistry.getOptionalValue(CONFIG_ENABLED).orElse(false);
    }

    @Override
    public VulnDataSource create() {
        if (!isDataSourceEnabled()) {
            LOGGER.info("Disabled; Not creating an instance");
            return null;
        }

        try {
            final var sources = objectMapper.readValue(this.configRegistry.getValue(CONFIG_SOURCES), CsafVulnDataSourceConfigs.CsafSources.class);
            return new CsafVulnDataSource(sources);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

}
