/**
 * lang-config.js
 * Central UI string dictionary for multi-language support.
 * Keys are semantic tokens used in data-i18n HTML attributes.
 * Add new languages by adding a matching key block below.
 */

const uiStrings = {

    EN: {
        // --- Document Titles (used for document.title per-page) ---
        title_dashboard: 'Dashboard | Network Console',
        title_topology: 'Topology | Network Console',
        title_assets: 'Assets | Network Console',
        title_traffic: 'Traffic | Network Console',
        title_security: 'Security & Audit | Network Console',
        title_access: 'Access Control | Network Console',
        title_alerts: 'Alerts | Network Console',
        title_settings: 'Settings | Network Console',

        // --- Sidebar Navigation ---
        nav_dashboard: 'Dashboard',
        nav_topology: 'Topology',
        nav_assets: 'Assets',
        nav_traffic: 'Traffic',
        nav_security: 'Security & Audit',
        nav_access: 'Access Control',
        nav_alerts: 'Alerts',
        nav_settings: 'Settings',
        nav_collapse: 'Collapse',
        nav_expand: 'Expand',

        // --- Topbar ---
        topbar_search_ph: 'Search device, IP or event...',  // placeholder
        topbar_lang_en: 'EN',
        topbar_lang_tr: 'TR',

        // --- Dashboard KPI Cards ---
        kpi_node_status: 'NODE STATUS',
        kpi_network_load: 'NETWORK LOAD',
        kpi_risk_magnitude: 'RISK MAGNITUDE',
        kpi_heartbeat: 'SYSTEM HEARTBEAT',
        kpi_active: 'ACTIVE',
        kpi_volatility: '↑ 12% VOLATILITY',
        kpi_nominal: 'NOMINAL',
        kpi_elevated: 'ELEVATED',
        kpi_critical: 'CRITICAL',
        kpi_subsystems: 'ALL SUB-SYSTEMS NOMINAL',
        kpi_active_threat: 'Active Threat',
        kpi_threats_display: 'Primary / Impacted',

        // --- Dashboard Charts ---
        chart_traffic_title: 'TRAFFIC VOLATILITY (24H PULSE)',
        chart_download: 'Download',
        chart_upload: 'Upload',
        chart_top_talkers: 'TOP TALKERS',
        chart_hours: ['00', '03', '06', '09', '12', '15', '18', '21', '24'],

        // --- Dashboard Table ---
        table_title: 'COMMAND SECURITY LOGS',
        table_view_all: 'VIEW ALL DATA →',
        table_priority: 'PRIORITY',
        table_event: 'EVENT',
        table_source: 'SOURCE ORIGIN',
        table_timestamp: 'TIMESTAMP',
        table_critical: 'Critical',
        table_warning: 'Warning',
        table_info: 'Info',

        // --- Assets Page ---
        assets_title: 'ASSET REGISTRY',
        assets_col_status: 'STATUS',
        assets_col_hostname: 'HOSTNAME',
        assets_col_ip: 'IP ADDRESS',
        assets_col_mac: 'MAC ADDRESS',
        assets_col_type: 'TYPE',
        assets_col_os: 'OS',
        assets_col_discovered: 'DISCOVERED',
        assets_col_actions: 'ACTIONS',
        assets_btn_approve: 'Approve',
        assets_btn_detail: 'Details',
        assets_pending: 'Pending',
        assets_search_ph: 'Filter by hostname, IP or MAC...',

        // --- Traffic Page ---
        traffic_title: 'LIVE TRAFFIC MONITOR',
        traffic_col_source: 'SOURCE',
        traffic_col_dest: 'DESTINATION',
        traffic_col_port: 'PORT',
        traffic_col_bytes: 'BYTES',
        traffic_col_time: 'TIME',

        // --- Security & Audit Page ---
        security_title: 'SECURITY & AUDIT COMMAND',
        security_threats: 'THREATS DETECTED',
        security_heatmap: 'SECTOR RISK HEATMAP',
        security_adversaries: 'TOP ADVERSARIES',
        security_score: 'Security Score',
        security_overall: 'Overall Status',
        security_attack_map: 'Threat Entry Points',
        security_live: 'LIVE',
        security_history: 'Threat History',
        security_scan_logs: 'AUTOMATED DIAGNOSTIC LOGS',
        security_col_ts: 'TIMESTAMP',
        security_col_target: 'TARGET NODE',
        security_col_ports: 'OPEN PORTS',
        security_col_finding: 'DIAGNOSTIC FINDING',
        security_col_risk: 'RISK LEVEL',
        security_reports: 'Audit Reports',
        security_report_pdf: 'Latest Audit Summary',
        security_report_csv: 'Export as CSV',
        security_btn_review: 'Review',
        security_synchronizing: 'SYNCHRONIZING...',
        security_fetching: 'Fetching alerts...',

        // --- Access Control Page ---
        access_title: 'ACCESS CONTROL',
        access_badge_allow: 'ALLOW',
        access_badge_deny: 'DENY',

        // --- Alerts Page ---
        alerts_title: 'ALERT CENTER',
        alerts_col_severity: 'SEVERITY',
        alerts_col_type: 'TYPE',
        alerts_col_device: 'DEVICE',
        alerts_col_time: 'TIME',

        // --- Settings Page ---
        settings_title: 'SETTINGS',

        // --- Common / Shared ---
        common_online: 'Online',
        common_offline: 'Offline',
        common_warning: 'Warning',
        common_isolated: 'Isolated',
        common_scanning: 'Under Scan',
        common_observing: 'Under Observation',
        common_ago: 'ago',
        common_minutes: 'min',
        common_unknown: 'Unknown',
    },

    TR: {
        // --- Document Titles ---
        title_dashboard: 'Panel | Ağ Konsolu',
        title_topology: 'Topoloji | Ağ Konsolu',
        title_assets: 'Varlıklar | Ağ Konsolu',
        title_traffic: 'Trafik | Ağ Konsolu',
        title_security: 'Güvenlik ve Denetim | Ağ Konsolu',
        title_access: 'Erişim Kontrolü | Ağ Konsolu',
        title_alerts: 'Alarmlar | Ağ Konsolu',
        title_settings: 'Ayarlar | Ağ Konsolu',

        // --- Sidebar Navigation ---
        nav_dashboard: 'Panel',
        nav_topology: 'Topoloji',
        nav_assets: 'Varlıklar',
        nav_traffic: 'Trafik',
        nav_security: 'Güvenlik ve Denetim',
        nav_access: 'Erişim Kontrolü',
        nav_alerts: 'Alarmlar',
        nav_settings: 'Ayarlar',
        nav_collapse: 'Daralt',
        nav_expand: 'Genişlet',

        // --- Topbar ---
        topbar_search_ph: 'Cihaz, IP veya olay ara...',
        topbar_lang_en: 'EN',
        topbar_lang_tr: 'TR',

        // --- Dashboard KPI Cards ---
        kpi_node_status: 'DÜĞÜM DURUMU',
        kpi_network_load: 'AĞ YÜKÜ',
        kpi_risk_magnitude: 'RİSK SEVİYESİ',
        kpi_heartbeat: 'SİSTEM NABZI',
        kpi_active: 'AKTİF',
        kpi_volatility: '↑ %12 VOLATİLİTE',
        kpi_nominal: 'NORMAL',
        kpi_elevated: 'YÜKSELMİŞ',
        kpi_critical: 'KRİTİK',
        kpi_subsystems: 'TÜM ALT SİSTEMLER NORMAL',
        kpi_active_threat: 'Aktif Tehdit',
        kpi_threats_display: 'Birincil / Etkilenen',

        // --- Dashboard Charts ---
        chart_traffic_title: 'TRAFİK VOLATİLİTESİ (24S NABIZ)',
        chart_download: 'İndirme',
        chart_upload: 'Yükleme',
        chart_top_talkers: 'EN AKTİF KONUŞANLAR',
        chart_hours: ['00', '03', '06', '09', '12', '15', '18', '21', '24'],

        // --- Dashboard Table ---
        table_title: 'KOMUTA GÜVENLİK KAYITLARI',
        table_view_all: 'TÜM VERİYİ GÖRÜNTÜLE →',
        table_priority: 'ÖNCELİK',
        table_event: 'OLAY',
        table_source: 'KAYNAK KÖKENİ',
        table_timestamp: 'ZAMAN DAMGASI',
        table_critical: 'Kritik',
        table_warning: 'Uyarı',
        table_info: 'Bilgi',

        // --- Assets Page ---
        assets_title: 'VARLIK KAYIT DEFTERİ',
        assets_col_status: 'DURUM',
        assets_col_hostname: 'CİHAZ ADI',
        assets_col_ip: 'IP ADRESİ',
        assets_col_mac: 'MAC ADRESİ',
        assets_col_type: 'TİP',
        assets_col_os: 'İŞLETİM SİSTEMİ',
        assets_col_discovered: 'KEŞFEDILDI',
        assets_col_actions: 'İŞLEMLER',
        assets_btn_approve: 'Onayla',
        assets_btn_detail: 'Detay',
        assets_pending: 'Beklemede',
        assets_search_ph: 'Cihaz adı, IP veya MAC ile filtrele...',

        // --- Traffic Page ---
        traffic_title: 'CANLI TRAFİK İZLEYİCİ',
        traffic_col_source: 'KAYNAK',
        traffic_col_dest: 'HEDEF',
        traffic_col_port: 'PORT',
        traffic_col_bytes: 'BYTE',
        traffic_col_time: 'ZAMAN',

        // --- Security & Audit Page ---
        security_title: 'GÜVENLİK VE DENETİM KOMUTASI',
        security_threats: 'TEHDİT TESPİT EDİLDİ',
        security_heatmap: 'SEKTÖR RİSK ISISI',
        security_adversaries: 'EN TEHLİKELİ KAYNAKLAR',
        security_score: 'Güvenlik Skoru',
        security_overall: 'Genel Durum',
        security_attack_map: 'Tehdit Giriş Noktaları',
        security_live: 'CANLI',
        security_history: 'Tehdit Geçmişi',
        security_scan_logs: 'OTOMATİK TANI KAYITLARI',
        security_col_ts: 'ZAMAN DAMGASI',
        security_col_target: 'HEDEF DÜĞÜM',
        security_col_ports: 'AÇIK PORTLAR',
        security_col_finding: 'TANI BULGULARI',
        security_col_risk: 'RİSK SEVİYESİ',
        security_reports: 'Denetim Raporları',
        security_report_pdf: 'Son Denetim Özeti',
        security_report_csv: 'CSV Olarak Dışa Aktar',
        security_btn_review: 'İncele',
        security_synchronizing: 'SENKRONİZE EDİLİYOR...',
        security_fetching: 'Alarmlar çekiliyor...',

        // --- Access Control Page ---
        access_title: 'ERİŞİM KONTROLÜ',
        access_badge_allow: 'İZİN VER',
        access_badge_deny: 'ENGELLE',

        // --- Alerts Page ---
        alerts_title: 'ALARM MERKEZİ',
        alerts_col_severity: 'ÖNEM',
        alerts_col_type: 'TİP',
        alerts_col_device: 'CİHAZ',
        alerts_col_time: 'ZAMAN',

        // --- Settings Page ---
        settings_title: 'AYARLAR',

        // --- Common / Shared ---
        common_online: 'Çevrimiçi',
        common_offline: 'Çevrimdışı',
        common_warning: 'Uyarı',
        common_isolated: 'İzole',
        common_scanning: 'Taranıyor',
        common_observing: 'Gözlem Altında',
        common_ago: 'önce',
        common_minutes: 'dk',
        common_unknown: 'Bilinmiyor',
    }
};
