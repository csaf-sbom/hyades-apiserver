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
package org.dependencytrack.datasource.vuln.csaf;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.plugin.api.config.ConfigRegistry;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;

import static org.dependencytrack.datasource.vuln.csaf.CsafVulnDataSourceConfigs.CONFIG_SOURCES;

public class SourcesManager {

    private final ConfigRegistry configRegistry;
    private final ObjectMapper objectMapper;

    public SourcesManager(
            ConfigRegistry configRegistry,
            ObjectMapper objectMapper
    ) {
        this.configRegistry = configRegistry;
        this.objectMapper = objectMapper;
    }

    static SourcesManager create(
            final ConfigRegistry configRegistry,
            final ObjectMapper objectMapper) {

        return new SourcesManager(configRegistry, objectMapper);
    }

    public List<CsafSource> getSources() {
        return configRegistry.getOptionalValue(CONFIG_SOURCES)
                .map(value -> deserializeSources(objectMapper, value))
                .orElse(new ArrayList<>());
    }

    public static String serializeSources(
            final ObjectMapper objectMapper,
            final List<CsafSource> sources) {
        try {
            return objectMapper.writeValueAsString(sources);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static List<CsafSource> deserializeSources(
            final ObjectMapper objectMapper,
            final String serializedSources) {
        try {
            return objectMapper.readValue(serializedSources, new TypeReference<>() {
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
