package org.dependencytrack.datasource.vuln.csaf;

import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;

import java.util.LinkedList;
import java.util.Queue;

public class CsafVulnDataSource implements VulnDataSource {

    private final Queue<String> advisoryQueue;

    public CsafVulnDataSource(CsafVulnDataSourceConfigs.CsafSources sources) {
        this.advisoryQueue = new LinkedList<>();
    }

    @Override
    public boolean hasNext() {
        return false;
    }

    @Override
    public Bom next() {
        return null;
    }

}
