# GreyCircuit Technologies — Insights & Blog Portal

Official production repository for the GreyCircuit Technologies Insights, Editorial, and Blog digital platform.

## Production Environment
- **Canonical Domain:** [https://blogs.greycircuit.tech](https://blogs.greycircuit.tech)
- **Main Corporate Portal:** [https://greycircuit.tech](https://greycircuit.tech)
- **Deployment Platform:** Cloudflare Pages

## Architecture & Features
- **Runtime:** Pure Static Web (HTML5, Modern CSS3, Vanilla ES6+ JavaScript).
- **Zero Build Step:** Runs directly in modern browsers without compilation or bundling.
- **Decoupled Architecture:** Completely standalone static repository with dedicated brand assets and vendor dependencies.
- **Dynamic Content:** Real-time PostgREST article retrieval from Supabase PostgreSQL.
- **Interactive Engagement:**
  - Anonymous article likes via SECURITY DEFINER PostgreSQL RPCs (`record_article_like`, `remove_article_like`) with client-hash fingerprinting and secret validation.
  - Moderated comment submissions protected by database-level rate limiting (3/minute, 15/hour) and SECURITY BARRIER views (`approved_comments`).
- **Content Sanitization:** Embedded DOMPurify (`vendor/dompurify/purify.min.js`) ensuring all dynamically rendered markdown/HTML is safely sanitized against XSS.

## Directory Structure
```
├── assets/                  # Brand assets
│   └── logo_transparent.png # Corporate brand mark
├── vendor/                  # Third-party runtime dependencies
│   └── dompurify/           # DOMPurify XSS sanitization library
├── article.html             # Dynamic article reader, likes & comment interface
├── config.js                # Active public Supabase configuration
├── config.example.js        # Configuration template
├── index.html               # Blog homepage, search & category filtering portal
├── robots.txt               # Search engine crawl directives
├── script.js                # Dynamic PostgREST client, search, likes & comment engine
├── sitemap.xml              # Canonical blog XML sitemap
└── styles.css               # Editorial design system tokens & responsive typography
```

## Configuration
Client-side Supabase configuration resides in `config.js`:
```javascript
window.__GCT_CONFIG__ = Object.freeze({
  supabaseUrl: 'https://<your-project-ref>.supabase.co',
  anonKey: 'sb_publishable_<your-public-anon-key>'
});
```
> **Security Policy:** This file must contain *only* public anonymous keys. Elevated service-role credentials must never be placed in this repository.

## Cloudflare Pages Deployment
- **Framework Preset:** None (Static HTML)
- **Build Command:** *(None / leave empty)*
- **Build Output Directory:** `/`
- **Root Directory:** `/`

## License
Proprietary & Confidential. All rights reserved © 2026 GreyCircuit Technologies Private Limited.
