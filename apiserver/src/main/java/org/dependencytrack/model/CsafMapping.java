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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.ForeignKey;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;

/**
 * JDO Entity representing a mapping between a CSAF document and a Vulnerability.
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CsafMapping {
    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    private Long id;

    @Persistent
    @ForeignKey(name="CSAFDOCUMENT_FK")
    @Column(name="CSAFDOCUMENT_ID")
    private CsafDocumentEntity csafDocument;

    @Persistent
    @ForeignKey(name="VULNERABILITY_FK")
    @Column(name="VULNERABILITY_ID")
    private Vulnerability vulnerability;

    public CsafMapping() {
    }

    public CsafMapping(CsafDocumentEntity csafDocument, Vulnerability vulnerability) {
        this.csafDocument = csafDocument;
        this.vulnerability = vulnerability;
    }

    public CsafMapping(Long id, CsafDocumentEntity csafDocument, Vulnerability vulnerability) {
        this.id = id;
        this.csafDocument = csafDocument;
        this.vulnerability = vulnerability;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public CsafDocumentEntity getCsafDocument() {
        return csafDocument;
    }

    public void setCsafDocument(CsafDocumentEntity csafDocument) {
        this.csafDocument = csafDocument;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }
}

