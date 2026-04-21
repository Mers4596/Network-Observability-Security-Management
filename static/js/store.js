// store.js — Central Application State Store
// Observer Pattern (Publish / Subscribe)
// Generic naming: appStore, refreshUI — no product-specific names.

const appStore = {

    // ── 1. Centralized State ──────────────────────────────────────────────────
    state: {
        devices: [],
        alerts: [],
        scans: [],
        auditLogs: [],
        trafficStats: {},
        trafficHeatmap: [],
        trafficTimeline: [],
        topTalkers: [],
        accessRules: [],
        topology: [],
        safe_zones: [],
        settings: {},
        riskHistory: [],
        // Live data persistence
        liveBandwidth: { dl: new Array(60).fill(0), ul: new Array(60).fill(0), labels: new Array(60).fill('') },
        liveTerminal: []
    },

    // ── 2. Observer Pattern ───────────────────────────────────────────────────
    observers: [],

    subscribe: function (fn) {
        if (typeof fn === 'function') {
            this.observers.push(fn);
        }
    },

    notifyObservers: function () {
        this.observers.forEach(fn => fn(this.state));
    },

    // ── 3. Data Loader ────────────────────────────────────────────────────────
    async loadData() {
        if (!this._initialLoadDone) {
            const cached = sessionStorage.getItem('nebula_store_cache');
            if (cached) {
                this.state = JSON.parse(cached);
                this.notifyObservers();
            }
        }
        try {
            console.log('[appStore] Syncing with backend...');

            const endpoints = [
                { key: 'devices', url: '/api/devices' },
                { key: 'alerts', url: '/api/alerts' },
                { key: 'safe_zones', url: '/api/safe-zones' },
                { key: 'dashboardStats', url: '/api/stats' },
                { key: 'trafficStats', url: '/api/traffic/stats' }, // Ensures traffic.html KPIs update
                { key: 'trafficHeatmap', url: '/api/traffic/heatmap' },
                { key: 'trafficTimeline', url: '/api/traffic-timeline' },
                { key: 'topTalkers', url: '/api/top-talkers' },
                { key: 'scans', url: '/api/scans' },
                { key: 'auditLogs', url: '/api/audit-logs' },
                { key: 'accessRules', url: '/api/rules' },
                { key: 'settings', url: '/api/settings' },
                { key: 'topology', url: '/api/topology' },
                { key: 'riskHistory', url: '/api/analytics/risk-history' },
                { key: 'trafficLogs', url: '/api/traffic' }
            ];

            const results = await Promise.allSettled(endpoints.map(e => fetch(e.url)));

            for (let i = 0; i < endpoints.length; i++) {
                const res = results[i];
                const key = endpoints[i].key;
                if (res.status === 'fulfilled' && res.value.ok) {
                    const data = await res.value.json();
                    if (key === 'safe_zones') {
                        this.state.safe_zones = data; // keep full objects {id, name, ip_range}
                    } else if (key === 'settings') {
                        this.state.settings = data.governance || {};
                        this.state.users = data.users || [];
                    } else if (key === 'topology') {
                        this.state.topology = data.links || [];
                    } else {
                        this.state[key] = data;
                    }
                }
            }

            // Cyber Contagion Algorithm
            this.runContagionLogic();

            sessionStorage.setItem('nebula_store_cache', JSON.stringify(this.state));
            this._initialLoadDone = true;

            this.notifyObservers();
        } catch (err) {
            console.error('[appStore] Sync failed:', err);
        }
    },

    runContagionLogic() {
        const highRiskIds = this.state.devices
            .filter(d => d.status !== 'Isolated' && d.risk_level > 80)
            .map(d => d.id);

        this.state.devices.forEach(device => {
            device.shadow_risk_flag = false;
            if (highRiskIds.length > 0) {
                const isNeighbor = highRiskIds.some(riskId => {
                    const riskNode = this.state.devices.find(d => d.id === riskId);
                    if (!riskNode) return false;
                    return (
                        (device.parent_id && device.parent_id === riskNode.parent_id) ||
                        device.id === riskNode.parent_id ||
                        device.parent_id === riskNode.id
                    ) && device.id !== riskId;
                });
                if (isNeighbor && device.risk_level <= 80 && device.status !== 'Isolated') {
                    device.shadow_risk_flag = true;
                }
            }
        });
    },

    // ── 4. Write Helpers ──────────────────────────────────────────────────────
    formatBandwidth: function (bps) {
        if (!bps || isNaN(bps)) return "0 bps";
        if (bps >= 1e9) return (bps / 1e9).toFixed(2) + " Gbps";
        if (bps >= 1e6) return (bps / 1e6).toFixed(2) + " Mbps";
        if (bps >= 1e3) return (bps / 1e3).toFixed(2) + " Kbps";
        return bps + " bps";
    },

    updateDeviceStatus: async function (device_id, action) {
        try {
            const endpoint = action === 'online' ? `/api/devices/approve/${device_id}` : `/api/devices/isolate/${device_id}`;
            const res = await fetch(endpoint, { method: 'POST' });
            if (res.ok) {
                await this.loadData();
            } else {
                console.error(`Failed to trigger ${action} for device ${device_id}`);
            }
        } catch (err) {
            console.error('Action failed:', err);
        }
    },

    scanDevice: async function (device_id) {
        try {
            const res = await fetch(`/api/devices/scan/${device_id}`, { method: 'POST' });
            if (res.ok) {
                await this.loadData();
            } else {
                console.error(`Failed to trigger scan for device ${device_id}`);
            }
        } catch (err) {
            console.error('Scan failed:', err);
        }
    },

    // ── Access Rule Helpers ──────────────────────────────────────────────────
    async addRule(ruleData) {
        try {
            const res = await fetch('/api/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(ruleData)
            });
            if (res.ok) {
                showToast('Rule successfully created', 'success');
                await this.loadData();
            } else {
                showToast('Failed to create rule', 'error');
            }
        } catch (err) { showToast('Network error while adding rule', 'error'); }
    },

    async toggleRule(ruleId) {
        try {
            const res = await fetch(`/api/rules/${ruleId}/toggle`, { method: 'PATCH' });
            if (res.ok) {
                showToast('Rule status updated', 'info');
                await this.loadData();
            } else {
                showToast('Failed to update rule status', 'error');
            }
        } catch (err) { showToast('Network error while toggling rule', 'error'); }
    },

    async deleteRule(ruleId) {
        try {
            const res = await fetch(`/api/rules/${ruleId}`, { method: 'DELETE' });
            if (res.ok) {
                showToast('Rule deleted successfully', 'success');
                await this.loadData();
            } else {
                showToast('Failed to delete rule', 'error');
            }
        } catch (err) { showToast('Network error while deleting rule', 'error'); }
    },

    async updateRule(ruleId, ruleData) {
        try {
            const res = await fetch(`/api/rules/${ruleId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(ruleData)
            });
            if (res.ok) {
                showToast('Rule updated successfully', 'success');
                await this.loadData();
            } else {
                showToast('Failed to update rule', 'error');
            }
        } catch (err) { showToast('Network error while updating rule', 'error'); }
    },

    async updateSettings(settingsData) {
        try {
            // Need to preserve existing settings to send full patch payload
            const currentSettings = this.state.settings || {};
            const payload = { ...currentSettings, ...settingsData };
            const res = await fetch('/api/settings', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (res.ok) {
                showToast('Ayarlar başarıyla kaydedildi (DB Onaylandı)', 'success');
                await this.loadData();
            } else {
                showToast('Failed to save settings', 'error');
            }
        } catch (err) { showToast('Network error while saving settings', 'error'); }
    },

    async updateRuleSchedule(ruleId, schedule) {
        try {
            const res = await fetch(`/api/rules/${ruleId}/schedule`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ schedule })
            });
            if (res.ok) await this.loadData();
        } catch (err) { console.error('Update schedule failed:', err); }
    },

    async addSafeZone(name, ip_range) {
        try {
            const res = await fetch('/api/safe-zones', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, ip_range })
            });
            if (res.ok) {
                showToast(`Zone '${name}' added`, 'success');
                await this.loadData();
            } else {
                const d = await res.json();
                showToast(d.error || 'Failed to add zone', 'error');
            }
        } catch (err) { showToast('Network error', 'error'); }
    },

    async deleteSafeZone(zoneId) {
        try {
            const res = await fetch(`/api/safe-zones/${zoneId}`, { method: 'DELETE' });
            if (res.ok) {
                showToast('Zone removed', 'success');
                await this.loadData();
            } else {
                showToast('Failed to remove zone', 'error');
            }
        } catch (err) { showToast('Network error', 'error'); }
    },

    // ── User Management Helpers ──────────────────────────────────────────────
    async addUser(userData) {
        try {
            const res = await fetch('/api/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            });
            if (res.ok) {
                if (typeof showToast !== 'undefined') showToast('Kullanıcı başarıyla eklendi', 'success');
                else alert('Kullanıcı başarıyla eklendi');
                await this.loadData();
            } else {
                const error = await res.json();
                if (typeof showToast !== 'undefined') showToast(error.error || 'Failed to add user', 'error');
                else alert(error.error || 'Failed to add user');
            }
        } catch (err) { 
            if (typeof showToast !== 'undefined') showToast('Network error while adding user', 'error'); 
            else alert('Network error while adding user');
        }
    },

    async updateUser(userId, updates) {
        try {
            const res = await fetch(`/api/users/${userId}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updates)
            });
            if (res.ok) {
                if (typeof showToast !== 'undefined') showToast('Kullanıcı başarıyla güncellendi', 'success');
                else alert('Kullanıcı başarıyla güncellendi');
                await this.loadData();
            } else {
                const error = await res.json();
                if (typeof showToast !== 'undefined') showToast(error.error || 'Failed to update user', 'error');
                else alert(error.error || 'Failed to update user');
            }
        } catch (err) {
            if (typeof showToast !== 'undefined') showToast('Network error while updating user', 'error');
            else alert('Network error while updating user');
        }
    },

    async deleteUser(userId) {
        try {
            const res = await fetch(`/api/users/${userId}`, {
                method: 'DELETE'
            });
            if (res.ok) {
                if (typeof showToast !== 'undefined') showToast('Kullanıcı silindi', 'success');
                else alert('Kullanıcı silindi');
                await this.loadData();
            } else {
                const error = await res.json();
                if (typeof showToast !== 'undefined') showToast(error.error || 'Failed to delete user', 'error');
                else alert(error.error || 'Failed to delete user');
            }
        } catch (err) {
            if (typeof showToast !== 'undefined') showToast('Network error while deleting user', 'error');
            else alert('Network error while deleting user');
        }
    }
};

// ============================================================
// Base Global UI Observer — refreshUI
// Handles cross-page DOM updates when state changes.
// ============================================================

window.refreshUI = function (state) {
    if (!state) return;

    // 1. Assets table
    const tableBody = document.getElementById('tableBody');
    if (tableBody && window._assetsFilterRender) {
        window._assetsFilterRender();
    }

    // 2. Dashboard alerts table
    const alertTableCard = document.getElementById('dashboardAlertsBody');
    if (alertTableCard) {
        alertTableCard.innerHTML = (state.alerts || []).slice(0, 5).map(alert => {
            const sClass = alert.severity === 'critical' ? 'alert-critical' : (alert.severity === 'warning' ? 'alert-warning' : '');
            const sLabel = alert.severity === 'critical' ? 'Critical' : (alert.severity === 'warning' ? 'Warning' : '<span style="color:#00E676;">Info</span>');
            return `
                <tr>
                    <td class="${sClass}">${sLabel}</td>
                    <td>${alert.type}</td>
                    <td>${alert.hostname}</td>
                    <td><span class="time-badge">${alert.timestamp}</span></td>
                </tr>
            `;
        }).join('');
    }

    // 3. Access Control rules
    const ruleList = document.getElementById('ruleList');
    const ruleCount = document.getElementById('activeRuleCount');
    if (ruleCount) ruleCount.textContent = `${state.accessRules.length} Kural`;

    if (ruleList) {
        if (!state.accessRules || state.accessRules.length === 0) {
            ruleList.innerHTML = '<div style="padding:20px; text-align:center; color:var(--text-muted); font-size:13px;">Kural bulunamadı</div>';
        } else {
            ruleList.innerHTML = state.accessRules.map(rule => {
                const actionUpper = (rule.action || 'Monitor').toUpperCase();
                const badgeClass = actionUpper === 'ALLOW' ? 'allow' : (actionUpper === 'BLOCK' ? 'deny' : 'monitor');
                // Encode rule object for inline onclick
                const ruleJson = encodeURIComponent(JSON.stringify(rule));
                return `
                    <div class="rule-item" draggable="true" data-priority="${rule.priority || 99}">
                        <div class="rule-header">
                            <span class="rule-title">${rule.rule_name || 'Undefined Rule'}</span>
                            <span class="rule-badge ${badgeClass}">${actionUpper}</span>
                        </div>
                        <div class="rule-desc">
                            <i class="fas fa-arrow-right"></i> Protocol: ${rule.protocol || 'All'}<br>
                            <span style="font-size:11px;">${rule.source || 'Any'} → ${rule.destination || 'Any'}</span>
                        </div>
                        <div class="rule-footer">
                            <div class="rule-actions">
                                <button class="rule-btn" onclick="appStore.deleteRule(${rule.id})" style="color:#FF4B5C;" title="Kuralı Sil">
                                    <i class="fas fa-trash"></i>
                                </button>
                                <button class="rule-btn" onclick="openRuleModal(JSON.parse(decodeURIComponent('${ruleJson}')))" title="Kuralı Düzenle" style="color:var(--neon-cyan);">
                                    <i class="fas fa-edit"></i>
                                </button>
                            </div>
                            <label class="switch rule-toggle">
                                <input type="checkbox" ${rule.status === 'Enabled' ? 'checked' : ''} onchange="appStore.toggleRule(${rule.id})">
                                <span class="slider"></span>
                            </label>
                        </div>
                    </div>
                `;
            }).join('');
        }
    }
};

// Subscribe the base observer
appStore.subscribe(window.refreshUI);

// ── 4. WebSockets: Real-Time Alerts ───────────────────────────────────────
appStore.initSocket = function () {
    const socket = io();

    socket.on('connect', () => {
        console.log('[appStore] WebSocket Connected');
    });

    socket.on('live_traffic_feed', (data) => {
        // Calculate estimated bandwidth
        const liveTotalMB = (data.live_bps / 8) / 1_000_000;
        const estDl = liveTotalMB * 0.7;
        const estUl = liveTotalMB * 0.3;

        // Shift and push data for bandwidth persistence
        appStore.state.liveBandwidth.labels.shift();
        appStore.state.liveBandwidth.labels.push('');
        
        appStore.state.liveBandwidth.dl.shift();
        appStore.state.liveBandwidth.dl.push(estDl);
        
        appStore.state.liveBandwidth.ul.shift();
        appStore.state.liveBandwidth.ul.push(estUl);

        // Keep terminal memory limited to 50
        if (data.packets && data.packets.length > 0) {
            data.packets.forEach(p => {
                appStore.state.liveTerminal.unshift(p);
            });

            if (appStore.state.liveTerminal.length > 50) {
                appStore.state.liveTerminal.length = 50;
            }
        }

        // Persist dynamically added live bounds across page transitions
        sessionStorage.setItem('nebula_store_cache', JSON.stringify(appStore.state));

        // Dispatch high-frequency live traffic directly to UI components
        // Avoids triggering full state re-renders for every packet batch
        const event = new CustomEvent('live_traffic_update', { detail: data });
        document.dispatchEvent(event);
    });

    socket.on('new_critical_alert', (newAlert) => {
        console.log('[appStore] Real-time Alert Received:', newAlert);

        // 1. Prepend to state
        this.state.alerts.unshift(newAlert);

        // 2. Keep state manageable (trim to 50)
        if (this.state.alerts.length > 50) {
            this.state.alerts.pop();
        }

        // 3. Notify UI immediately
        this.notifyObservers();

        // 4. Dispatch a custom event for page-specific logic (like toasts)
        const event = new CustomEvent('ws_alert', { detail: newAlert });
        document.dispatchEvent(event);
    });
};

// Boot sequence
document.addEventListener('DOMContentLoaded', async () => {
    await appStore.loadData();
    appStore.initSocket();

    // Periodic sync every 5 seconds
    setInterval(() => { appStore.loadData(); }, 5000);
});
