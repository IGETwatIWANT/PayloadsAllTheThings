/* BASzy Ai - Dashboard JavaScript */

const API = '';
let currentScanId = null;
let pollInterval = null;

// ─── Navigation ─────────────────────────────────────────────────────

function switchView(viewName) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('view-' + viewName).classList.add('active');
    document.querySelector(`[data-view="${viewName}"]`).classList.add('active');

    if (viewName === 'payloads') loadPayloadStats();
    if (viewName === 'mitre') loadMitreCoverage();
    if (viewName === 'findings') loadScanList();
    if (viewName === 'settings') loadSettings();
    if (viewName === 'dashboard') refreshDashboard();
}

// ─── API Helpers ────────────────────────────────────────────────────

async function api(path, options = {}) {
    const res = await fetch(API + path, {
        headers: { 'Content-Type': 'application/json', ...options.headers },
        ...options,
    });
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    return res.json();
}

// ─── Dashboard ──────────────────────────────────────────────────────

async function refreshDashboard() {
    try {
        const status = await api('/api/status');
        document.getElementById('engine-status').textContent = status.ai_available ? 'AI Online' : 'Heuristic Mode';
        document.getElementById('engine-status').style.background = status.ai_available
            ? 'rgba(16,185,129,0.15)' : 'rgba(234,179,8,0.15)';
        document.getElementById('engine-status').style.color = status.ai_available ? '#10b981' : '#eab308';
        document.getElementById('stat-scans').textContent = status.total_scans;

        const aiEl = document.getElementById('ai-status');
        if (status.ai_available) {
            aiEl.textContent = 'AI: Online';
            aiEl.className = 'status-badge online';
        } else {
            aiEl.textContent = 'AI: Offline';
            aiEl.className = 'status-badge offline';
        }

        // Payload stats
        try {
            const pstats = await api('/api/payloads/stats');
            document.getElementById('stat-payloads').textContent = pstats.total_payloads.toLocaleString();
        } catch(e) {}

        // Load scans
        const scans = await api('/api/scans');
        const container = document.getElementById('active-scans');
        if (scans.length === 0) {
            container.innerHTML = '<p class="empty-state">No active scans. Start one from the New Scan tab.</p>';
        } else {
            container.innerHTML = scans.map(s => `
                <div class="scan-card">
                    <div>
                        <div class="scan-target">${escHtml(s.target)}</div>
                        <div class="scan-meta">${s.scan_id} | ${s.status} | ${s.findings_count} findings</div>
                    </div>
                    <div>
                        <span class="sev-badge sev-${s.status === 'complete' ? 'info' : 'medium'}">${s.status}</span>
                    </div>
                </div>
            `).join('');
        }

        // Aggregate findings
        let counts = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const scan of scans) {
            if (scan.findings_count > 0) {
                try {
                    const findings = await api(`/api/scans/${scan.scan_id}/findings`);
                    findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

                    // Recent findings table
                    const tbody = document.getElementById('recent-findings-body');
                    tbody.innerHTML = findings.slice(0, 10).map(f => `
                        <tr>
                            <td>${escHtml(f.finding_id)}</td>
                            <td><span class="sev-badge sev-${f.severity}">${f.severity}</span></td>
                            <td>${escHtml(f.module)}</td>
                            <td>${escHtml(f.title.substring(0, 60))}</td>
                            <td>${escHtml(f.target)}</td>
                        </tr>
                    `).join('');
                } catch(e) {}
            }
        }
        document.getElementById('stat-critical').textContent = counts.critical;
        document.getElementById('stat-high').textContent = counts.high;
        document.getElementById('stat-medium').textContent = counts.medium;
        document.getElementById('stat-low').textContent = counts.low;

    } catch (e) {
        console.error('Dashboard refresh error:', e);
    }
}

// ─── Scan ───────────────────────────────────────────────────────────

async function loadModuleCheckboxes() {
    try {
        const modules = await api('/api/modules');
        const grid = document.getElementById('module-checkboxes');
        grid.innerHTML = modules.map(m => `
            <label class="module-check">
                <input type="checkbox" value="${m.name}" checked>
                <span>${m.name}</span>
            </label>
        `).join('');
    } catch (e) {
        console.error('Failed to load modules:', e);
    }
}

async function startScan(event) {
    event.preventDefault();

    const checkedModules = Array.from(document.querySelectorAll('#module-checkboxes input:checked')).map(c => c.value);

    const payload = {
        target: document.getElementById('scan-target').value,
        authorized_by: document.getElementById('scan-authorized').value,
        auth_level: document.getElementById('scan-auth-level').value,
        max_rps: parseInt(document.getElementById('scan-rps').value),
        modules: checkedModules,
        enable_zeroday: document.getElementById('scan-zeroday').checked,
        dry_run: document.getElementById('scan-dryrun').checked,
        proxy: document.getElementById('scan-proxy').value,
    };

    try {
        const result = await api('/api/scans', { method: 'POST', body: JSON.stringify(payload) });
        currentScanId = result.scan_id;

        document.getElementById('scan-progress-panel').style.display = 'block';
        document.getElementById('scan-progress-text').textContent = `Scan ${result.scan_id} started against ${payload.target}`;

        pollInterval = setInterval(() => pollScanProgress(currentScanId, checkedModules), 2000);
    } catch (e) {
        alert('Failed to start scan: ' + e.message);
    }
}

async function pollScanProgress(scanId, allModules) {
    try {
        const status = await api(`/api/scans/${scanId}`);
        document.getElementById('scan-progress-bar').style.width = status.progress + '%';
        document.getElementById('scan-progress-text').textContent =
            `${status.status} | ${status.findings_count} findings | ${status.elapsed_seconds.toFixed(0)}s elapsed`;

        const list = document.getElementById('scan-live-modules');
        list.innerHTML = allModules.map(m => {
            const cls = status.modules_completed.includes(m) ? 'complete' :
                        (status.modules_remaining.includes(m) ? 'pending' : 'running');
            return `<span class="module-status ${cls}">${m}</span>`;
        }).join('');

        if (status.status === 'complete' || status.status === 'error' || status.status === 'stopped') {
            clearInterval(pollInterval);
            pollInterval = null;
            document.getElementById('scan-progress-text').textContent =
                `Scan ${status.status}. ${status.findings_count} findings in ${status.elapsed_seconds.toFixed(0)}s.`;
        }
    } catch (e) {
        console.error('Poll error:', e);
    }
}

async function stopCurrentScan() {
    if (!currentScanId) return;
    try {
        await api(`/api/scans/${currentScanId}/stop`, { method: 'POST' });
    } catch (e) {}
}

// ─── Findings ───────────────────────────────────────────────────────

async function loadScanList() {
    try {
        const scans = await api('/api/scans');
        const select = document.getElementById('findings-scan-select');
        select.innerHTML = '<option value="">Select a scan...</option>' +
            scans.map(s => `<option value="${s.scan_id}">${s.scan_id} - ${s.target} (${s.findings_count} findings)</option>`).join('');
    } catch (e) {}
}

async function loadFindings(scanId) {
    if (!scanId) return;
    try {
        const findings = await api(`/api/scans/${scanId}/findings`);
        const tbody = document.getElementById('findings-body');

        if (findings.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No findings for this scan.</td></tr>';
            return;
        }

        tbody.innerHTML = findings.map(f => `
            <tr>
                <td>${escHtml(f.finding_id)}</td>
                <td><span class="sev-badge sev-${f.severity}">${f.severity}</span></td>
                <td>${escHtml(f.module)}</td>
                <td>${escHtml(f.title.substring(0, 60))}</td>
                <td style="font-family:var(--font-mono);font-size:11px;">${escHtml(f.evidence.substring(0, 80))}</td>
                <td style="font-family:var(--font-mono);font-size:11px;">${escHtml((f.payload || '').substring(0, 40))}</td>
            </tr>
        `).join('');

        // Severity bar
        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
        const total = findings.length || 1;
        const bar = document.getElementById('severity-bar');
        bar.innerHTML = Object.entries(counts).map(([sev, count]) =>
            `<div class="sev-segment" style="width:${(count/total)*100}%;background:var(--${sev === 'info' ? 'info' : sev});"></div>`
        ).join('');
    } catch (e) {
        console.error('Load findings error:', e);
    }
}

// ─── Payloads ───────────────────────────────────────────────────────

async function loadPayloadStats() {
    try {
        const stats = await api('/api/payloads/stats');
        document.getElementById('payload-stats').innerHTML =
            `<span class="payload-stat">Categories: <strong>${stats.categories}</strong></span>
             <span class="payload-stat">Inline Payloads: <strong>${stats.inline_payloads.toLocaleString()}</strong></span>
             <span class="payload-stat">Intruder Payloads: <strong>${stats.intruder_payloads.toLocaleString()}</strong></span>
             <span class="payload-stat">Total: <strong>${stats.total_payloads.toLocaleString()}</strong></span>`;

        const cats = await api('/api/payloads/categories');
        document.getElementById('payload-categories').innerHTML = cats.map(c => `
            <div class="category-card" onclick="searchPayloadsByCategory('${c.canonical_name}')">
                <div class="cat-name">${escHtml(c.name)}</div>
                <div class="cat-count">${c.total_payloads} payloads</div>
            </div>
        `).join('');
    } catch (e) {}
}

async function searchPayloads() {
    const query = document.getElementById('payload-search').value;
    if (!query) return;
    try {
        const result = await api('/api/payloads/search', {
            method: 'POST',
            body: JSON.stringify({ query, limit: 50 }),
        });

        const table = document.getElementById('payload-results-table');
        table.style.display = 'table';
        document.getElementById('payload-results-body').innerHTML = result.results.map(r => `
            <tr>
                <td>${escHtml(r.category)}</td>
                <td style="font-family:var(--font-mono);font-size:12px;">${escHtml(r.payload.substring(0, 100))}</td>
                <td style="font-size:11px;color:var(--text-dim);">${escHtml((r.source || '').substring(0, 30))}</td>
            </tr>
        `).join('');
    } catch (e) {}
}

function searchPayloadsByCategory(category) {
    document.getElementById('payload-search').value = category;
    searchPayloads();
}

// ─── MITRE ──────────────────────────────────────────────────────────

async function loadMitreCoverage() {
    try {
        const data = await api('/api/mitre/coverage');
        const matrix = document.getElementById('mitre-matrix');
        matrix.innerHTML = Object.entries(data.coverage).map(([tactic, techniques]) => `
            <div class="mitre-tactic">
                <h3>${escHtml(tactic)}</h3>
                ${techniques.map(t => `<div class="mitre-technique covered">${escHtml(t)}</div>`).join('')}
            </div>
        `).join('');
    } catch (e) {}
}

// ─── Settings ───────────────────────────────────────────────────────

async function loadSettings() {
    try {
        const status = await api('/api/status');
        document.getElementById('engine-info').innerHTML = `
            <p>Version: ${status.version}</p>
            <p>AI Available: ${status.ai_available ? 'Yes' : 'No'}</p>
            <p>Payload DB: ${status.payload_db_loaded ? 'Loaded' : 'Not loaded'}</p>
            <p>Active Scans: ${status.active_scans}</p>
        `;

        const ai = await api('/api/ai/status');
        document.getElementById('ai-models-list').innerHTML = ai.available
            ? ai.models.map(m => `<p style="font-family:var(--font-mono)">${m.name}</p>`).join('')
            : '<p class="empty-state">AI backend not available. Start Ollama to enable AI features.</p>';
    } catch (e) {}
}

// ─── Utils ──────────────────────────────────────────────────────────

function escHtml(str) {
    const d = document.createElement('div');
    d.textContent = str || '';
    return d.innerHTML;
}

// ─── Init ───────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    refreshDashboard();
    loadModuleCheckboxes();
    setInterval(refreshDashboard, 10000);
});
