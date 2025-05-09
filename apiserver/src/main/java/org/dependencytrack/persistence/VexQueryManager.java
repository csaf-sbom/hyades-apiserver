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

import alpine.resources.AlpineRequest;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vex;

import javax.jdo.PersistenceManager;
import java.util.Date;

final class VexQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    VexQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    VexQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Creates a new Vex.
     * @param project the Project to create a Vex for
     * @param imported the Date when the vex was imported
     * @return a new Vex object
     */
    public Vex createVex(Project project, Date imported, Vex.Format format, String specVersion, Integer vexVersion, String serialNumber) {
        final Vex vex = new Vex();
        vex.setImported(imported);
        vex.setProject(project);
        vex.setVexFormat(format);
        vex.setSpecVersion(specVersion);
        vex.setVexVersion(vexVersion);
        vex.setSerialNumber(serialNumber);
        return persist(vex);
    }

}
