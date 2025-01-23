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

import alpine.common.validation.RegexSequence;
import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.io.Serializable;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;

import org.datanucleus.metadata.JdbcType;

/**
 * Model for configured CSAF source Entities.
 *
 * 
 * @since 5.6.0 //TODO set when merged
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CsafEntity implements Serializable {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    private long csafEntryId;

    @Persistent(name = "TYPE")
    private CsafEntityType entityType;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    @Persistent(name = "NAME")
    private String name;

    @Persistent
    @Column(name = "URL")
    @NotBlank
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String url;

    @Persistent
    @Column(name = "ENABLED")
    @NotNull
    private boolean enabled;

    @Persistent
    @Column(name = "CONTENT") //jdbcType = "BLOB"
    private byte[] content;

    public CsafEntity() {
        // no args for jdo
    }

    public CsafEntity(CsafEntityType entityType, String name, String url) {
        this.entityType = entityType;
        this.name = name;
        this.url = url;
    }

    public long getCsafEntryId() {
        return csafEntryId;
    }

    public CsafEntityType getEntityType() {
        return entityType;
    }

    public void setEntityType(CsafEntityType entityType) {
        this.entityType = entityType;
    }

    public void setCsafEntryId(long csafEntryId) {
        this.csafEntryId = csafEntryId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }
}
