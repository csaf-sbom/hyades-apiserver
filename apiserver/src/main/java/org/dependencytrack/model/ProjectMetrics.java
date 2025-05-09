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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.ForeignKey;
import javax.jdo.annotations.ForeignKeyAction;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import java.io.Serializable;
import java.util.Date;

/**
 * Metrics specific to individual projects.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProjectMetrics implements Serializable {

    private static final long serialVersionUID = 8741534340846353210L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @ForeignKey(name = "PROJECTMETRICS_PROJECT_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private Project project;

    @Persistent
    @Column(name = "CRITICAL")
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private int critical;

    @Persistent
    @Column(name = "HIGH")
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private int high;

    @Persistent
    @Column(name = "MEDIUM")
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private int medium;

    @Persistent
    @Column(name = "LOW")
    @NotNull
    private int low;

    @Persistent
    @Column(name = "UNASSIGNED_SEVERITY", allowsNull = "true") // New column, must allow nulls on existing databases)
    private Integer unassigned;

    @Persistent
    @Column(name = "VULNERABILITIES")
    private int vulnerabilities;

    @Persistent
    @Column(name = "VULNERABLECOMPONENTS")
    private int vulnerableComponents;

    @Persistent
    @Column(name = "COMPONENTS")
    private int components;

    @Persistent
    @Column(name = "SUPPRESSED")
    private int suppressed;

    @Persistent
    @Column(name = "FINDINGS_TOTAL", allowsNull = "true") // New column, must allow nulls on existing databases)
    private Integer findingsTotal;

    @Persistent
    @Column(name = "FINDINGS_AUDITED", allowsNull = "true") // New column, must allow nulls on existing databases)
    private Integer findingsAudited;

    @Persistent
    @Column(name = "FINDINGS_UNAUDITED", allowsNull = "true") // New column, must allow nulls on existing databases)
    private Integer findingsUnaudited;

    @Persistent
    @Column(name = "RISKSCORE")
    private double inheritedRiskScore;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_FAIL", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsFail;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_WARN", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsWarn;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_INFO", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private Integer policyViolationsInfo;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_TOTAL", allowsNull = "true")
    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsTotal;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_AUDITED", allowsNull = "true")
    // New column, must allow nulls on existing databases)
    private Integer policyViolationsAudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_UNAUDITED", allowsNull = "true")
    // New column, must allow nulls on existing databases)
    private Integer policyViolationsUnaudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_SECURITY_TOTAL", allowsNull = "true")
    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsSecurityTotal;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_SECURITY_AUDITED", allowsNull = "true")
    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsSecurityAudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_SECURITY_UNAUDITED", allowsNull = "true")
    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsSecurityUnaudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_LICENSE_TOTAL", allowsNull = "true")
    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsLicenseTotal;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_LICENSE_AUDITED", allowsNull = "true")
    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsLicenseAudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_LICENSE_UNAUDITED", allowsNull = "true")
    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsLicenseUnaudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_OPERATIONAL_TOTAL", allowsNull = "true")
    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsOperationalTotal;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_OPERATIONAL_AUDITED", allowsNull = "true")
    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsOperationalAudited;

    @Persistent
    @Column(name = "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED", allowsNull = "true")
    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsOperationalUnaudited;

    @Persistent
    @Column(name = "FIRST_OCCURRENCE", allowsNull = "false")
    @NotNull
    @Index(name = "PROJECTMETRICS_FIRST_OCCURRENCE_IDX")
    @Schema(type = "integer", format = "int64", requiredMode = Schema.RequiredMode.REQUIRED, description = "UNIX epoch timestamp in milliseconds")
    private Date firstOccurrence;

    @Persistent
    @Column(name = "LAST_OCCURRENCE", allowsNull = "false")
    @NotNull
    @Index(name = "PROJECTMETRICS_LAST_OCCURRENCE_IDX")
    @Schema(type = "integer", format = "int64", requiredMode = Schema.RequiredMode.REQUIRED, description = "UNIX epoch timestamp in milliseconds")
    private Date lastOccurrence;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public int getCritical() {
        return critical;
    }

    public void setCritical(int critical) {
        this.critical = critical;
    }

    public int getHigh() {
        return high;
    }

    public void setHigh(int high) {
        this.high = high;
    }

    public int getMedium() {
        return medium;
    }

    public void setMedium(int medium) {
        this.medium = medium;
    }

    public int getLow() {
        return low;
    }

    public void setLow(int low) {
        this.low = low;
    }

    public int getUnassigned() {
        return unassigned != null ? unassigned : 0;
    }

    public void setUnassigned(int unassigned) {
        this.unassigned = unassigned;
    }

    public int getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(int vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public int getVulnerableComponents() {
        return vulnerableComponents;
    }

    public void setVulnerableComponents(int vulnerableComponents) {
        this.vulnerableComponents = vulnerableComponents;
    }

    public int getComponents() {
        return components;
    }

    public void setComponents(int components) {
        this.components = components;
    }

    public int getSuppressed() {
        return suppressed;
    }

    public void setSuppressed(int suppressed) {
        this.suppressed = suppressed;
    }

    public int getFindingsTotal() {
        return findingsTotal != null ? findingsTotal : 0;
    }

    public void setFindingsTotal(int findingsTotal) {
        this.findingsTotal = findingsTotal;
    }

    public int getFindingsAudited() {
        return findingsAudited != null ? findingsAudited : 0;
    }

    public void setFindingsAudited(int findingsAudited) {
        this.findingsAudited = findingsAudited;
    }

    public int getFindingsUnaudited() {
        return findingsUnaudited != null ? findingsUnaudited : 0;
    }

    public void setFindingsUnaudited(int findingsUnaudited) {
        this.findingsUnaudited = findingsUnaudited;
    }

    public double getInheritedRiskScore() {
        return inheritedRiskScore;
    }

    public void setInheritedRiskScore(double inheritedRiskScore) {
        this.inheritedRiskScore = inheritedRiskScore;
    }

    public int getPolicyViolationsFail() {
        return policyViolationsFail != null ? policyViolationsFail : 0;
    }

    public void setPolicyViolationsFail(int policyViolationsFail) {
        this.policyViolationsFail = policyViolationsFail;
    }

    public int getPolicyViolationsWarn() {
        return policyViolationsWarn != null ? policyViolationsWarn : 0;
    }

    public void setPolicyViolationsWarn(int policyViolationsWarn) {
        this.policyViolationsWarn = policyViolationsWarn;
    }

    public int getPolicyViolationsInfo() {
        return policyViolationsInfo != null ? policyViolationsInfo : 0;
    }

    public void setPolicyViolationsInfo(int policyViolationsInfo) {
        this.policyViolationsInfo = policyViolationsInfo;
    }

    public int getPolicyViolationsTotal() {
        return policyViolationsTotal != null ? policyViolationsTotal : 0;
    }

    public void setPolicyViolationsTotal(int policyViolationsTotal) {
        this.policyViolationsTotal = policyViolationsTotal;
    }

    public int getPolicyViolationsAudited() {
        return policyViolationsAudited != null ? policyViolationsAudited : 0;
    }

    public void setPolicyViolationsAudited(int policyViolationsAudited) {
        this.policyViolationsAudited = policyViolationsAudited;
    }

    public int getPolicyViolationsUnaudited() {
        return policyViolationsUnaudited != null ? policyViolationsUnaudited : 0;
    }

    public void setPolicyViolationsUnaudited(int policyViolationsUnaudited) {
        this.policyViolationsUnaudited = policyViolationsUnaudited;
    }

    public int getPolicyViolationsSecurityTotal() {
        return policyViolationsSecurityTotal != null ? policyViolationsSecurityTotal : 0;
    }

    public void setPolicyViolationsSecurityTotal(int policyViolationsSecurityTotal) {
        this.policyViolationsSecurityTotal = policyViolationsSecurityTotal;
    }

    public int getPolicyViolationsSecurityAudited() {
        return policyViolationsSecurityAudited != null ? policyViolationsSecurityAudited : 0;
    }

    public void setPolicyViolationsSecurityAudited(int policyViolationsSecurityAudited) {
        this.policyViolationsSecurityAudited = policyViolationsSecurityAudited;
    }

    public int getPolicyViolationsSecurityUnaudited() {
        return policyViolationsSecurityUnaudited != null ? policyViolationsSecurityUnaudited : 0;
    }

    public void setPolicyViolationsSecurityUnaudited(int policyViolationsSecurityUnaudited) {
        this.policyViolationsSecurityUnaudited = policyViolationsSecurityUnaudited;
    }

    public int getPolicyViolationsLicenseTotal() {
        return policyViolationsLicenseTotal != null ? policyViolationsLicenseTotal : 0;
    }

    public void setPolicyViolationsLicenseTotal(int policyViolationsLicenseTotal) {
        this.policyViolationsLicenseTotal = policyViolationsLicenseTotal;
    }

    public int getPolicyViolationsLicenseAudited() {
        return policyViolationsLicenseAudited != null ? policyViolationsLicenseAudited : 0;
    }

    public void setPolicyViolationsLicenseAudited(int policyViolationsLicenseAudited) {
        this.policyViolationsLicenseAudited = policyViolationsLicenseAudited;
    }

    public int getPolicyViolationsLicenseUnaudited() {
        return policyViolationsLicenseUnaudited != null ? policyViolationsLicenseUnaudited : 0;
    }

    public void setPolicyViolationsLicenseUnaudited(int policyViolationsLicenseUnaudited) {
        this.policyViolationsLicenseUnaudited = policyViolationsLicenseUnaudited;
    }

    public int getPolicyViolationsOperationalTotal() {
        return policyViolationsOperationalTotal != null ? policyViolationsOperationalTotal : 0;
    }

    public void setPolicyViolationsOperationalTotal(int policyViolationsOperationalTotal) {
        this.policyViolationsOperationalTotal = policyViolationsOperationalTotal;
    }

    public int getPolicyViolationsOperationalAudited() {
        return policyViolationsOperationalAudited != null ? policyViolationsOperationalAudited : 0;
    }

    public void setPolicyViolationsOperationalAudited(int policyViolationsOperationalAudited) {
        this.policyViolationsOperationalAudited = policyViolationsOperationalAudited;
    }

    public int getPolicyViolationsOperationalUnaudited() {
        return policyViolationsOperationalUnaudited != null ? policyViolationsOperationalUnaudited : 0;
    }

    public void setPolicyViolationsOperationalUnaudited(int policyViolationsOperationalUnaudited) {
        this.policyViolationsOperationalUnaudited = policyViolationsOperationalUnaudited;
    }

    public Date getFirstOccurrence() {
        return firstOccurrence;
    }

    public void setFirstOccurrence(Date firstOccurrence) {
        this.firstOccurrence = firstOccurrence;
    }

    public Date getLastOccurrence() {
        return lastOccurrence;
    }

    public void setLastOccurrence(Date lastOccurrence) {
        this.lastOccurrence = lastOccurrence;
    }

    @JsonIgnore
    public boolean hasChanged(final ProjectMetrics comparedTo) {
        return comparedTo == null
                || comparedTo.getCritical() != this.critical
                || comparedTo.getHigh() != this.high
                || comparedTo.getMedium() != this.medium
                || comparedTo.getLow() != this.low
                || comparedTo.getUnassigned() != this.unassigned
                || comparedTo.getVulnerabilities() != this.vulnerabilities
                || comparedTo.getSuppressed() != this.suppressed
                || comparedTo.getFindingsTotal() != this.findingsTotal
                || comparedTo.getFindingsAudited() != this.findingsAudited
                || comparedTo.getFindingsUnaudited() != this.findingsUnaudited
                || comparedTo.getInheritedRiskScore() != this.inheritedRiskScore
                || comparedTo.getPolicyViolationsFail() != this.policyViolationsFail
                || comparedTo.getPolicyViolationsWarn() != this.policyViolationsWarn
                || comparedTo.getPolicyViolationsInfo() != this.policyViolationsInfo
                || comparedTo.getPolicyViolationsTotal() != this.policyViolationsTotal
                || comparedTo.getPolicyViolationsAudited() != this.policyViolationsAudited
                || comparedTo.getPolicyViolationsUnaudited() != this.policyViolationsUnaudited
                || comparedTo.getPolicyViolationsSecurityTotal() != this.policyViolationsSecurityTotal
                || comparedTo.getPolicyViolationsSecurityAudited() != this.policyViolationsSecurityAudited
                || comparedTo.getPolicyViolationsSecurityUnaudited() != this.policyViolationsSecurityUnaudited
                || comparedTo.getPolicyViolationsLicenseTotal() != this.policyViolationsLicenseTotal
                || comparedTo.getPolicyViolationsLicenseAudited() != this.policyViolationsLicenseAudited
                || comparedTo.getPolicyViolationsLicenseUnaudited() != this.policyViolationsLicenseUnaudited
                || comparedTo.getPolicyViolationsOperationalTotal() != this.policyViolationsOperationalTotal
                || comparedTo.getPolicyViolationsOperationalAudited() != this.policyViolationsOperationalAudited
                || comparedTo.getPolicyViolationsOperationalUnaudited() != this.policyViolationsOperationalUnaudited
                || comparedTo.getComponents() != this.components
                || comparedTo.getVulnerableComponents() != this.vulnerableComponents;
    }

}
