/**
 * core.js
 * Application core utilities.
 * Handles: multi-language i18n, DOM scanning, language persistence.
 *
 * Depends on: lang-config.js (uiStrings) loaded before this file.
 * Generic naming: appLang, uiStrings — no product-specific names.
 */

// ─────────────────────────────────────────────
// i18n Engine
// ─────────────────────────────────────────────

const appLang = {

    /** Currently active language code, e.g. 'EN' or 'TR' */
    current: 'EN',

    /** Storage key for localStorage persistence */
    _storageKey: 'ui_language',

    /** Supported language codes */
    supported: ['EN', 'TR'],

    /**
     * Returns a translated string for the given key.
     * Falls back to the key itself if not found.
     * @param {string} key  - Token from uiStrings, e.g. 'nav_dashboard'
     * @param {string} [lang] - Override language (defaults to appLang.current)
     */
    t(key, lang) {
        const code = (lang || this.current).toUpperCase();
        const dict = (typeof uiStrings !== 'undefined' && uiStrings[code]) ? uiStrings[code] : {};
        return dict[key] !== undefined ? dict[key] : key;
    },

    /**
     * Initialise the i18n engine:
     *  1. Read saved preference from localStorage
     *  2. Apply language to the document
     *  3. Update the topbar language toggle to show the active state
     */
    initLanguage() {
        const saved = localStorage.getItem(this._storageKey);
        const lang = (saved && this.supported.includes(saved.toUpperCase()))
            ? saved.toUpperCase()
            : 'EN';
        this.setLanguage(lang, false); // false = don't fire the change event on init
        this._updateToggleButtons(lang);
    },

    /**
     * Applies a language to the entire DOM:
     *  1. Updates this.current
     *  2. Persists to localStorage
     *  3. Scans [data-i18n] elements and updates their textContent
     *  4. Scans [data-i18n-placeholder] elements and updates placeholder=""
     *  5. Updates document.title if the page defines a data-page-key meta tag
     *  6. Fires a custom 'languagechange' event so charts/dynamic UI can re-render
     *
     * @param {string}  lang       - 'EN' or 'TR'
     * @param {boolean} [fireEvent=true] - Whether to fire the 'languagechange' event
     */
    setLanguage(lang, fireEvent = true) {
        const code = lang.toUpperCase();
        if (!this.supported.includes(code)) {
            console.warn(`[appLang] Unsupported language: "${lang}". Falling back to EN.`);
            return;
        }

        this.current = code;
        localStorage.setItem(this._storageKey, code);

        // Set html[lang] attribute for accessibility / SEO
        document.documentElement.lang = code.toLowerCase();

        // ── 1. Translate all [data-i18n] text nodes ──────────────
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            const translation = this.t(key, code);
            if (translation !== key) {
                el.textContent = translation;
            }
        });

        // ── 2. Translate [data-i18n-placeholder] inputs ──────────
        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            const key = el.getAttribute('data-i18n-placeholder');
            const translation = this.t(key, code);
            if (translation !== key) {
                el.placeholder = translation;
            }
        });

        // ── 3. Update document.title ──────────────────────────────
        //   Pages declare: <meta name="i18n-title" content="title_dashboard">
        const titleMeta = document.querySelector('meta[name="i18n-title"]');
        if (titleMeta) {
            const titleKey = titleMeta.getAttribute('content');
            const titleStr = this.t(titleKey, code);
            if (titleStr !== titleKey) document.title = titleStr;
        }

        // ── 4. Update toggle button active states ─────────────────
        this._updateToggleButtons(code);

        // ── 5. Dispatch custom event for chart/dynamic re-renders ─
        if (fireEvent) {
            document.dispatchEvent(new CustomEvent('languagechange', {
                detail: { lang: code, t: (key) => this.t(key, code) }
            }));
        }
    },

    /**
     * Mark the correct language button as active in the topbar.
     * @param {string} code - Active language code
     */
    _updateToggleButtons(code) {
        document.querySelectorAll('.lang-btn').forEach(btn => {
            const btnLang = btn.getAttribute('data-lang');
            btn.classList.toggle('active', btnLang === code);
        });
    }
};

// ─────────────────────────────────────────────
// Boot
// ─────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    appLang.initLanguage();
});

// ─────────────────────────────────────────────
// Usage helpers (globally accessible)
// ─────────────────────────────────────────────

/**
 * Shorthand translate function.
 * Usage in JS: t('nav_dashboard')  → 'Dashboard' or 'Panel'
 */
window.t = (key) => appLang.t(key);


// ─────────────────────────────────────────────
// Toast Notification System
// ─────────────────────────────────────────────

/**
 * Displays a floating toast notification.
 * @param {string} message  - Text to display
 * @param {'success'|'error'|'info'|'warning'} type - Visual style
 * @param {number} [duration=3500] - Auto-dismiss delay in ms (0 = sticky)
 */
window.showToast = function (message, type = 'info', duration = 3500) {
    // Ensure a container exists
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        Object.assign(container.style, {
            position: 'fixed',
            bottom: '28px',
            right: '28px',
            zIndex: '99999',
            display: 'flex',
            flexDirection: 'column',
            gap: '10px',
            pointerEvents: 'none'
        });
        document.body.appendChild(container);
    }

    const colors = {
        success: { bg: 'rgba(0,230,118,0.12)', border: '#00e676', icon: '✔' },
        error: { bg: 'rgba(255,75,43,0.12)', border: '#ff4b2b', icon: '✖' },
        warning: { bg: 'rgba(243,156,18,0.12)', border: '#f39c12', icon: '⚠' },
        info: { bg: 'rgba(0,242,255,0.10)', border: '#00f2ff', icon: 'ℹ' }
    };
    const { bg, border, icon } = colors[type] || colors.info;

    const toast = document.createElement('div');
    toast.innerHTML = `<span style="font-size:14px;margin-right:8px;">${icon}</span>${message}`;
    Object.assign(toast.style, {
        background: bg,
        border: `1px solid ${border}`,
        borderLeft: `4px solid ${border}`,
        color: '#e0e0e0',
        padding: '12px 20px',
        borderRadius: '8px',
        fontSize: '13px',
        fontFamily: 'Outfit, sans-serif',
        maxWidth: '340px',
        backdropFilter: 'blur(12px)',
        boxShadow: `0 4px 20px rgba(0,0,0,0.4), 0 0 12px ${border}33`,
        pointerEvents: 'auto',
        opacity: '0',
        transform: 'translateX(20px)',
        transition: 'opacity 0.25s ease, transform 0.25s ease'
    });

    container.appendChild(toast);

    // Animate in
    requestAnimationFrame(() => {
        toast.style.opacity = '1';
        toast.style.transform = 'translateX(0)';
    });

    // Auto-dismiss
    if (duration > 0) {
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(20px)';
            setTimeout(() => toast.remove(), 280);
        }, duration);
    }

    return toast;
};


// ─────────────────────────────────────────────
// Device Action Helper
// ─────────────────────────────────────────────

/**
 * Sends a POST action to the device API, shows a toast, then
 * immediately refreshes the store so the UI reflects the change.
 *
 * @param {'isolate'|'restore'|'scan'|'approve'} action - Route fragment
 * @param {string} deviceId   - Device ID
 * @param {string} [deviceName] - Human-readable device name for the toast
 */
window.deviceAction = async function (action, deviceId, deviceName = deviceId) {
    const labels = {
        isolate: 'Isolating',
        restore: 'Restoring',
        scan: 'Scanning',
        approve: 'Approving'
    };

    const inProgress = showToast(
        `${labels[action] || action} <strong>${deviceName}</strong>…`,
        'info', 0   // sticky until we replace it
    );

    try {
        const res = await fetch(`/api/devices/${action}/${deviceId}`, { method: 'POST' });
        const data = await res.json();

        inProgress.style.opacity = '0';
        inProgress.style.transform = 'translateX(20px)';
        setTimeout(() => inProgress.remove(), 280);

        if (res.ok && data.success) {
            const actionLabels = {
                isolate: 'isolated',
                restore: 'restored',
                scan: 'scan started',
                approve: 'approved'
            };
            showToast(
                `<strong>${deviceName}</strong> ${actionLabels[action] || action}. Action logged.`,
                'success'
            );
        } else {
            showToast(data.error || 'Action failed. Check server logs.', 'error', 5000);
        }
    } catch (err) {
        inProgress.remove();
        showToast(`Network error: ${err.message}`, 'error', 5000);
    }

    // Immediately refresh device list — don't wait for 5s poll interval
    if (typeof appStore !== 'undefined') {
        await appStore.loadData();
    }
};
