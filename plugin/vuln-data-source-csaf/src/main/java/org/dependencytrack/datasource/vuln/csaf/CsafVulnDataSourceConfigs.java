package org.dependencytrack.datasource.vuln.csaf;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.List;

public class CsafVulnDataSourceConfigs {

    record CsafSources(List<CsafSource> sources) {

    }

    record CsafSource(String name, URL url) {
    }

    public static final RuntimeConfigDefinition<Boolean> CONFIG_ENABLED;
    static final RuntimeConfigDefinition<String> CONFIG_SOURCES;

    static {
        final URL defaultApiUrl;
        try {
            defaultApiUrl = URI.create("https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json").toURL();
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Failed to parse default API URL", e);
        }

        final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());;
        final String defaultSources;
        try {
            defaultSources = objectMapper.writeValueAsString(new CsafSources(List.of(new CsafSource("WID-Bund", defaultApiUrl))));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize default sources", e);
        }

        CONFIG_ENABLED = new RuntimeConfigDefinition<>(
                "enabled",
                "Whether the CSAF data source should be enabled",
                ConfigTypes.BOOLEAN,
                /* defaultValue */ false,
                /* isRequired */ false,
                /* isSecret */ false);
        CONFIG_SOURCES =  new RuntimeConfigDefinition<>(
                "alias.sync.enabled",
                "Whether to include alias information in vulnerability data",
                ConfigTypes.STRING,
                defaultSources,
                /* isRequired */ false,
                /* isSecret */ false);
    }

    private CsafVulnDataSourceConfigs() {
    }

}
