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

import java.net.URL;

/**
 * A CSAF source, either an aggregator or a provider.
 *
 * @since 5.7.0
 */
public class CsafSource {

    String name;

    URL url;

    boolean aggregator;

    public CsafSource() {}

    public CsafSource(String name, URL url, boolean isAggregator) {
        this.name = name;
        this.url = url;
        this.aggregator = isAggregator;
    }

    public String getName() {
        return name;
    }

    public URL getUrl() {
        return url;
    }

    public boolean getAggregator() {
        return aggregator;
    }

}
