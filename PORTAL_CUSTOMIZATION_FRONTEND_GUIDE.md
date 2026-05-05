# Portal Customization — Public Portal Frontend Integration Guide

This document explains how the captive portal frontend (`isp-landing-page`) should consume the portal settings API and apply each setting at runtime.

**Key point on themes:** The theme names (`ocean_blue`, `emerald_green`, etc.) are strings stored in the database and returned by the API. The actual hex colour values are defined **here in the frontend** — the JS reads the theme name and injects the matching CSS variables into the page. Nothing is fetched from the server for the colours themselves.

---

## Table of Contents

1. [Where Settings Come From](#1-where-settings-come-from)
2. [Theme Colour Definitions](#2-theme-colour-definitions)
3. [Applying the Theme](#3-applying-the-theme)
4. [Applying Each Setting](#4-applying-each-setting)
5. [Full Integration Snippet](#5-full-integration-snippet)
6. [Support Phone — Removing Hardcoded Values](#6-support-phone--removing-hardcoded-values)

---

## 1. Where Settings Come From

The portal already calls `GET /api/public/portal/{identity}` on load — this is the single combined request that returns router info, plans, and ads. **Portal settings should be added to this same response** as a `portal_settings` key so the frontend still only makes one network request.

Update `get_portal_data()` in `public_routes.py` to also query `PortalSettings` and include the result:

```python
# Inside get_portal_data() in public_routes.py — add this query alongside the existing ones
from app.db.models import PortalSettings

portal_settings_result = await db.execute(
    select(PortalSettings).where(PortalSettings.user_id == router_obj.user_id)
)
portal_settings = portal_settings_result.scalar_one_or_none()
```

Then include `_build_public_response(portal_settings, reseller)` in the return dict under `"portal_settings"`.

The frontend then reads `data.portal_settings` from the already-existing `fetchPortalData()` response.

---

## 2. Theme Colour Definitions

These live **in the portal JS** — copy this object into `script.js` (or a separate `portal-theme.js`). The API returns only the theme name; the JS does the colour lookup.

```js
const PORTAL_THEMES = {
  ocean_blue: {
    '--primary':        '#3b82f6',
    '--primary-light':  '#60a5fa',
    '--primary-dark':   '#2563eb',
    '--accent':         '#06b6d4',
    '--bg':             '#f0f9ff',
    '--bg-warm':        '#e0f2fe',
    '--shadow-glow':    '0 4px 20px rgba(59, 130, 246, 0.25)',
  },
  emerald_green: {
    '--primary':        '#10b981',
    '--primary-light':  '#34d399',
    '--primary-dark':   '#059669',
    '--accent':         '#06b6d4',
    '--bg':             '#f0fdf4',
    '--bg-warm':        '#dcfce7',
    '--shadow-glow':    '0 4px 20px rgba(16, 185, 129, 0.25)',
  },
  sunset_orange: {
    '--primary':        '#E85D04',
    '--primary-light':  '#F48C06',
    '--primary-dark':   '#DC2F02',
    '--accent':         '#FFBA08',
    '--bg':             '#FFFCF2',
    '--bg-warm':        '#FFF8E8',
    '--shadow-glow':    '0 4px 20px rgba(232, 93, 4, 0.25)',
  },
  midnight_purple: {
    '--primary':        '#7c3aed',
    '--primary-light':  '#a78bfa',
    '--primary-dark':   '#5b21b6',
    '--accent':         '#ec4899',
    '--bg':             '#faf5ff',
    '--bg-warm':        '#ede9fe',
    '--shadow-glow':    '0 4px 20px rgba(124, 58, 237, 0.25)',
  },
  rose_gold: {
    '--primary':        '#e11d48',
    '--primary-light':  '#fb7185',
    '--primary-dark':   '#be123c',
    '--accent':         '#f59e0b',
    '--bg':             '#fff1f2',
    '--bg-warm':        '#ffe4e6',
    '--shadow-glow':    '0 4px 20px rgba(225, 29, 72, 0.25)',
  },
  slate_gray: {
    '--primary':        '#475569',
    '--primary-light':  '#64748b',
    '--primary-dark':   '#334155',
    '--accent':         '#0ea5e9',
    '--bg':             '#f8fafc',
    '--bg-warm':        '#f1f5f9',
    '--shadow-glow':    '0 4px 20px rgba(71, 85, 105, 0.25)',
  },
};
```

> `sunset_orange` matches the current hardcoded values in `styles003.css` — so the portal looks identical to today if no theme is saved.

---

## 3. Applying the Theme

Call this once after `fetchPortalData()` resolves:

```js
function applyPortalTheme(themeName) {
  const theme = PORTAL_THEMES[themeName] || PORTAL_THEMES['ocean_blue'];
  const root = document.documentElement;
  Object.entries(theme).forEach(([prop, value]) => {
    root.style.setProperty(prop, value);
  });
  // Also update the PWA theme-color meta tag
  const metaTheme = document.querySelector('meta[name="theme-color"]');
  if (metaTheme) metaTheme.setAttribute('content', theme['--primary']);
}
```

---

## 4. Applying Each Setting

### Ads section

```js
function applyShowAds(show) {
  const showcase = document.querySelector('.marketplace-showcase');
  if (showcase) showcase.style.display = show ? '' : 'none';
}
```

### Welcome banner / title

```js
function applyWelcomeBanner(settings) {
  if (!settings.show_welcome_banner) {
    // hide the tagline / welcome subtitle area
    document.querySelector('.tagline')?.style.setProperty('display', 'none');
    return;
  }
  if (settings.welcome_title) {
    document.querySelector('.logo').textContent = settings.welcome_title;
    document.title = `${settings.welcome_title} - Get Connected`;
  }
  if (settings.welcome_subtitle) {
    const tagline = document.querySelector('.tagline');
    if (tagline) tagline.textContent = settings.welcome_subtitle;
  }
}
```

### Company logo

```js
function applyLogo(logoUrl) {
  if (!logoUrl) return;
  const brandIcon = document.querySelector('.brand-icon');
  if (brandIcon) {
    brandIcon.outerHTML = `<img src="${logoUrl}" alt="Logo" class="brand-logo" style="height:32px;width:auto;border-radius:4px;">`;
  }
}
```

### Announcement banner

Add this HTML just below the `<header>` in `index.html`:

```html
<div class="announcement-banner hidden" id="announcementBanner">
  <span class="announcement-icon" id="announcementIcon"></span>
  <span class="announcement-text" id="announcementText"></span>
</div>
```

Add to `styles003.css`:

```css
.announcement-banner {
  padding: 10px 16px;
  text-align: center;
  font-size: 0.9rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}
.announcement-banner.type-info    { background: #dbeafe; color: #1e40af; }
.announcement-banner.type-warning { background: #fef3c7; color: #92400e; }
.announcement-banner.type-success { background: #d1fae5; color: #065f46; }
```

Apply with JS:

```js
function applyAnnouncement(settings) {
  if (!settings.show_announcement || !settings.announcement_text) return;
  const banner = document.getElementById('announcementBanner');
  const textEl = document.getElementById('announcementText');
  if (!banner || !textEl) return;
  const icons = { info: 'ℹ️', warning: '⚠️', success: '✅' };
  document.getElementById('announcementIcon').textContent =
    icons[settings.announcement_type] || 'ℹ️';
  textEl.textContent = settings.announcement_text;
  banner.classList.remove('hidden', 'type-info', 'type-warning', 'type-success');
  banner.classList.add(`type-${settings.announcement_type || 'info'}`);
}
```

### Reconnect section

```js
function applyReconnectButton(show) {
  const section = document.getElementById('reconnectSection');
  if (section) section.style.display = show ? '' : 'none';
}
```

### Plans section title

```js
function applyPlansSectionTitle(title) {
  const el = document.querySelector('#mpesaSection h2.section-title');
  if (el && title) el.textContent = title;
}
```

### Social links row

Add a social links block to `index.html` (hidden by default):

```html
<div class="social-links hidden" id="socialLinksRow">
  <a href="#" id="socialFacebook" target="_blank" rel="noopener" class="social-link">📘 Facebook</a>
  <a href="#" id="socialWhatsapp" target="_blank" rel="noopener" class="social-link">💬 WhatsApp</a>
  <a href="#" id="socialInstagram" target="_blank" rel="noopener" class="social-link">📸 Instagram</a>
</div>
```

Apply with JS:

```js
function applySocialLinks(settings) {
  if (!settings.show_social_links) return;
  const row = document.getElementById('socialLinksRow');
  if (!row) return;
  if (settings.facebook_url)    document.getElementById('socialFacebook').href    = settings.facebook_url;
  if (settings.whatsapp_group_url) document.getElementById('socialWhatsapp').href = settings.whatsapp_group_url;
  if (settings.instagram_url)   document.getElementById('socialInstagram').href   = settings.instagram_url;
  const hasAny = settings.facebook_url || settings.whatsapp_group_url || settings.instagram_url;
  if (hasAny) row.classList.remove('hidden');
}
```

---

## 5. Full Integration Snippet

In `script.js`, inside the `.then(data => { ... })` block of `fetchPortalData()`, add after the existing router/plans/ads handling:

```js
// ---- Portal settings ----
if (data.portal_settings) {
  const s = data.portal_settings;

  applyPortalTheme(s.color_theme);
  applyShowAds(s.show_ads !== false);          // default true
  applyWelcomeBanner(s);
  applyLogo(s.company_logo_url);
  applyAnnouncement(s);
  applyReconnectButton(s.show_reconnect_button !== false);
  applyPlansSectionTitle(s.plans_section_title);
  applySocialLinks(s);

  // Footer
  if (s.footer_text) {
    document.querySelector('.portal-footer')?.textContent = s.footer_text;
  }

  // Language (hook for future i18n)
  if (s.portal_language && s.portal_language !== 'en') {
    document.documentElement.lang = s.portal_language;
    // TODO: load language strings for 'sw' or 'fr'
  }
}
```

---

## 6. Support Phone — Removing Hardcoded Values

The phone number `0795635364` is currently hardcoded in `index.html` in at least 5 places. The API already returns `support_phone` via `data.router.support_phone` and there is an `updateSupportPhone()` function in `script.js`. The fix is:

1. Replace every `href="tel:0795635364"` in `index.html` with `href="tel:"` and add an `id` or shared class, e.g. `class="support-tel"`.
2. Update `updateSupportPhone()` to target all of them:

```js
function updateSupportPhone(phone) {
  if (!phone) return;
  const formatted = phone.startsWith('+') ? phone : `+254${phone.replace(/^0/, '')}`;
  document.querySelectorAll('.support-tel').forEach(el => {
    el.href = `tel:${formatted}`;
  });
  // Also apply portal_support_whatsapp if available
}
```

Also replace the `"Bitwave Soko Wifi"` `<title>` tag and PWA name in `manifest.json` — both should be set dynamically from `welcome_title` or `business_name` after the API responds.
