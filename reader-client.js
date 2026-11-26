/**
 * GREYCIRCUIT TECHNOLOGIES — Reader Identity, Profile, & Privacy Client
 * Manages Mode A (Google OAuth) and Mode B (Pseudonymous Guest Sessions)
 * Strictly client-side safe; communicates only via public PostgREST / Supabase Auth endpoints.
 */

(() => {
  'use strict';

  const STORAGE_KEYS = {
    SESSION: 'gct_reader_auth_session',
    GUEST_ID: 'gct_guest_identity',
    GUEST_SECRET: 'gct_guest_secret',
    CONSENT: 'gct_privacy_consent_v2026',
    LIKES_CACHE: 'gct_reader_likes_cache',
    PROFILE_DRAFT: 'gct_reader_profile_draft',
    BOOKMARKS_CACHE: 'gct_reader_bookmarks_cache'
  };

  /**
   * Extensible Identity Providers Registry
   * Add new OAuth/SSO identity providers here without altering modal markup.
   */
  const AUTH_PROVIDERS_CONFIG = [
    {
      id: 'google',
      name: 'Google',
      iconSvg: `<svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path fill="#EA4335" d="M12 5c1.6 0 3 .6 4.1 1.6l3.1-3.1C17.3 1.8 14.8 1 12 1 7.4 1 3.5 3.6 1.6 7.4l3.7 2.9C6.2 7.3 8.8 5 12 5z"/><path fill="#4285F4" d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5c-.3 1.5-1.1 2.8-2.4 3.7l3.7 2.9c2.2-2 3.7-5 3.7-8.8z"/><path fill="#FBBC05" d="M5.3 14.7c-.2-.7-.4-1.5-.4-2.4 0-.9.2-1.7.4-2.4L1.6 7c-.8 1.6-1.3 3.4-1.3 5s.5 3.4 1.3 5l3.7-2.3z"/><path fill="#34A853" d="M12 23c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3.2 0-5.8-2.2-6.7-5.3L1.6 16C3.5 19.8 7.4 23 12 23z"/></svg>`,
      enabled: true,
      backendEnabled: null,
      checkConfigured: function() {
        const cfg = window.__GCT_CONFIG__ || {};
        if (this.backendEnabled === false) return false;
        return Boolean(cfg.supabaseUrl && cfg.anonKey);
      },
      action: (client) => client.signInWithGoogle()
    }
  ];

  class ReaderClient {
    constructor() {
      this.supabase = null;
      this.session = null;
      this.guest = null;
      this.profile = null;
      this._lastKnownCloudUpdatedAt = null;
      this._isExchangingCode = false;
      this._isSavingProfile = false;
      this.initPromise = this.init();
    }

    async init() {
      this.initSupabaseClient();
      this.loadStoredSession();
      await this.handleOAuthCallback();
      await this.ensureSessionSynchronized();
      await this.ensureAuthenticatedSession();
      this.ensureGuestIdentity();
      this.bindGlobalEvents();
      this.syncAuthStateAcrossUI();
      this.initConsentBanner();
      this.checkProviderAvailability();
    }

    initSupabaseClient() {
      try {
        const cfg = window.__GCT_CONFIG__ || {};
        if (window.supabase && typeof window.supabase.createClient === 'function' && cfg.supabaseUrl && cfg.anonKey) {
          this.supabase = window.supabase.createClient(cfg.supabaseUrl, cfg.anonKey, {
            auth: {
              flowType: 'pkce',
              storageKey: STORAGE_KEYS.SESSION,
              autoRefreshToken: true,
              persistSession: true,
              detectSessionInUrl: true
            }
          });

          // Single authoritative listener for all Supabase Auth lifecycle events
          this.supabase.auth.onAuthStateChange(async (event, session) => {
            console.log('[GCT Auth] onAuthStateChange event:', event, Boolean(session));
            if (event === 'SIGNED_IN' || event === 'TOKEN_REFRESHED' || event === 'USER_UPDATED' || event === 'INITIAL_SESSION') {
              if (session) {
                this.session = session;
                this.syncAuthStateAcrossUI();
                this.dispatchAuthChangeEvent(session);
              }
            } else if (event === 'SIGNED_OUT') {
              this.session = null;
              this._lastKnownCloudUpdatedAt = null;
              this.syncAuthStateAcrossUI();
              this.dispatchAuthChangeEvent(null);
            }
          });
        }
      } catch (err) {
        console.warn('[GCT Auth] Failed to initialize Supabase client:', err);
      }
    }

    async ensureSessionSynchronized() {
      if (this.supabase?.auth && typeof this.supabase.auth.getSession === 'function') {
        try {
          const { data, error } = await this.supabase.auth.getSession();
          if (data?.session) {
            this.session = data.session;
          } else if (!data?.session && this.session) {
            const nowSec = Math.floor(Date.now() / 1000);
            if (this.session.expires_at && this.session.expires_at <= nowSec && !this.session.refresh_token) {
              this.session = null;
            }
          }
        } catch (err) {
          console.warn('[GCT Auth] Session synchronization notice:', err);
        }
      }
    }

    async ensureAuthenticatedSession() {
      if (!this.supabase?.auth) return null;
      try {
        const { data, error } = await this.supabase.auth.getSession();
        if (data?.session) {
          const nowSec = Math.floor(Date.now() / 1000);
          if (data.session.expires_at && data.session.expires_at <= nowSec) {
            console.log('[GCT Auth] Current session expired, attempting token refresh...');
            const { data: refreshData, error: refreshErr } = await this.supabase.auth.refreshSession();
            if (refreshData?.session) {
              this.session = refreshData.session;
              return refreshData.session;
            }
          } else {
            this.session = data.session;
            return data.session;
          }
        }
        // No valid session: automatically establish Supabase Anonymous Auth session
        if (typeof this.supabase.auth.signInAnonymously === 'function') {
          console.log('[GCT Auth] Establishing anonymous reader session via signInAnonymously()...');
          const { data: anonData, error: anonErr } = await this.supabase.auth.signInAnonymously();
          if (anonErr) {
            console.warn('[GCT Auth] Anonymous sign-in notice:', anonErr.message);
            return null;
          }
          if (anonData?.session) {
            this.session = anonData.session;
            this.syncAuthStateAcrossUI();
            this.dispatchAuthChangeEvent(anonData.session);
            return anonData.session;
          }
        }
      } catch (err) {
        console.warn('[GCT Auth] ensureAuthenticatedSession caught notice:', err);
      }
      return null;
    }

    async checkProviderAvailability() {
      const cfg = window.__GCT_CONFIG__ || {};
      if (!cfg.supabaseUrl || !cfg.anonKey) return;
      try {
        const res = await fetch(`${cfg.supabaseUrl}/auth/v1/settings`, {
          headers: { apikey: cfg.anonKey }
        });
        if (res.ok) {
          const data = await res.json();
          if (data && data.external) {
            const googleProv = AUTH_PROVIDERS_CONFIG.find(p => p.id === 'google');
            if (googleProv) {
              googleProv.backendEnabled = Boolean(data.external.google);
              const modal = document.getElementById('reader-profile-modal');
              if (modal && modal.classList.contains('is-open')) {
                this.renderAuthProviders();
              }
            }
          }
        }
      } catch (e) {
        // network or CORS error, fall back silently
      }
    }

    /* -------------------------------------------------------------------------
     * 1. SESSION & IDENTITY INITIALIZATION
     * ---------------------------------------------------------------------- */
    loadStoredSession() {
      try {
        const raw = localStorage.getItem(STORAGE_KEYS.SESSION);
        if (raw) {
          const parsed = JSON.parse(raw);
          const nowSec = Math.floor(Date.now() / 1000);
          // Keep session if not expired OR if refresh_token is present for background refresh
          if (parsed.expires_at && parsed.expires_at > nowSec) {
            this.session = parsed;
          } else if (parsed.refresh_token) {
            this.session = parsed;
          } else {
            localStorage.removeItem(STORAGE_KEYS.SESSION);
            this.session = null;
          }
        }
      } catch (err) {
        console.warn('[GCT Auth] Error reading stored session:', err);
      }
    }

    ensureGuestIdentity() {
      try {
        let guestId = localStorage.getItem(STORAGE_KEYS.GUEST_ID);
        let guestSecret = localStorage.getItem(STORAGE_KEYS.GUEST_SECRET);

        if (!guestId || guestId.length < 16) {
          const rand = typeof crypto !== 'undefined' && crypto.randomUUID
            ? crypto.randomUUID().replace(/-/g, '')
            : Math.random().toString(36).substring(2) + Date.now().toString(36);
          guestId = 'gct_guest_' + rand;
          localStorage.setItem(STORAGE_KEYS.GUEST_ID, guestId);
        }

        if (!guestSecret || guestSecret.length < 16) {
          const randSecret = typeof crypto !== 'undefined' && crypto.randomUUID
            ? crypto.randomUUID().replace(/-/g, '')
            : Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
          guestSecret = 'gct_sec_' + randSecret;
          localStorage.setItem(STORAGE_KEYS.GUEST_SECRET, guestSecret);
        }

        this.guest = {
          id: guestId,
          secret: guestSecret,
          name: localStorage.getItem('gct_guest_saved_name') || 'Guest Reader',
          email: localStorage.getItem('gct_guest_saved_email') || ''
        };
      } catch {
        this.guest = { id: 'gct_guest_fallback', secret: 'gct_sec_fallback', name: 'Guest Reader', email: '' };
      }
    }

    async handleOAuthCallback() {
      if (this._isExchangingCode) return;

      const hash = window.location.hash;
      const search = window.location.search;

      // 1. Detect and handle OAuth Error in Hash or Search Query (e.g. access_denied, signups disabled)
      let errorParam = null;
      let errorDesc = null;
      let isQueryError = false;

      if (hash && (hash.includes('error=') || hash.includes('error_description='))) {
        try {
          const p = new URLSearchParams(hash.substring(1));
          errorParam = p.get('error');
          errorDesc = p.get('error_description');
        } catch {}
      } else if (search && (search.includes('error=') || search.includes('error_description='))) {
        try {
          const p = new URLSearchParams(search);
          errorParam = p.get('error');
          errorDesc = p.get('error_description');
          isQueryError = true;
        } catch {}
      }

      if (errorParam || errorDesc) {
        try {
          const rawMsg = errorDesc || errorParam || 'Authentication was cancelled or failed.';
          const errorText = rawMsg.replace(/\+/g, ' ');
          console.warn('[GCT Auth] OAuth callback error received:', errorParam, errorText);

          // Clean URL without losing existing query parameters (such as ?slug=...)
          if (isQueryError) {
            const p = new URLSearchParams(window.location.search);
            p.delete('error');
            p.delete('error_code');
            p.delete('error_description');
            const remaining = p.toString();
            const cleanUrl = window.location.pathname + (remaining ? `?${remaining}` : '') + (window.location.hash || '');
            window.history.replaceState({}, document.title, cleanUrl);
          } else {
            // Hash error: clear hash only, preserving search query intact
            const cleanUrl = window.location.pathname + window.location.search;
            window.history.replaceState({}, document.title, cleanUrl);
          }

          // Specific handling for signup-disabled condition (Supabase disable_signup: true)
          const lower = errorText.toLowerCase();
          const isSignupDisabled = (
            lower.includes('signup') ||
            lower.includes('signups not allowed') ||
            lower.includes('user registration is disabled') ||
            lower.includes('registration') ||
            (errorParam === 'access_denied' && (lower.includes('not allowed') || lower.includes('instance') || lower.includes('otp')))
          );

          if (isSignupDisabled) {
            this.showToast('Public reader registration is currently closed. Only pre-authorized accounts may sign in.', 'warning');
          } else {
            this.showToast(`Authentication notice: ${errorText}`, 'warning');
          }

          // Clean up transient return context on error
          try {
            sessionStorage.removeItem('gct_oauth_return_url');
            sessionStorage.removeItem('gct_oauth_scroll_y');
          } catch {}
        } catch (e) {
          console.warn('[GCT Auth] Error handling callback failure:', e);
        }
        return;
      }

      // 2. Detect and process PKCE Authorization Code (?code=...)
      if (search && search.includes('code=')) {
        const searchParams = new URLSearchParams(search);
        const authCode = searchParams.get('code');
        const authFlowId = searchParams.get('sb_flow_id');
        if (authCode) {
          this._isExchangingCode = true;
          try {
            let session = null;
            let user = null;

            if (this.supabase && this.supabase.auth && typeof this.supabase.auth.exchangeCodeForSession === 'function') {
              const exchangeOpts = authFlowId ? { flowId: authFlowId } : undefined;
              const { data, error } = await this.supabase.auth.exchangeCodeForSession(authCode, exchangeOpts);
              if (error) {
                console.warn('[GCT Auth] PKCE exchangeCodeForSession returned error:', error);
                const lower = (error.message || '').toLowerCase();
                if (lower.includes('signup') || lower.includes('not allowed') || lower.includes('disabled')) {
                  this.showToast('Public reader registration is currently closed. Only pre-authorized accounts may sign in.', 'warning');
                } else if (lower.includes('verifier not found') || lower.includes('missing')) {
                  this.showToast('Authentication session could not be verified. Please sign in again.', 'warning');
                } else {
                  this.showToast(`Authentication notice: ${error.message || 'Authorization code exchange failed.'}`, 'warning');
                }
              } else if (data && data.session) {
                session = data.session;
                user = data.user || data.session.user;
              }
            } else {
              // Direct endpoint fallback for PKCE exchange if SDK is not present
              const cfg = window.__GCT_CONFIG__ || {};
              let rawVerifier = null;
              if (authFlowId) {
                rawVerifier = localStorage.getItem(`${STORAGE_KEYS.SESSION}-flow-${authFlowId}-code-verifier`);
              }
              if (!rawVerifier) {
                rawVerifier = localStorage.getItem(`${STORAGE_KEYS.SESSION}-code-verifier`);
              }
              if (!rawVerifier) {
                for (let i = 0; i < localStorage.length; i++) {
                  const key = localStorage.key(i);
                  if (key && key.startsWith(STORAGE_KEYS.SESSION) && key.endsWith('-code-verifier')) {
                    rawVerifier = localStorage.getItem(key);
                    break;
                  }
                }
              }

              let codeVerifier = null;
              if (rawVerifier) {
                try {
                  const parsed = JSON.parse(rawVerifier);
                  codeVerifier = typeof parsed === 'string' ? parsed : rawVerifier;
                } catch {
                  codeVerifier = rawVerifier;
                }
              }

              if (codeVerifier && cfg.supabaseUrl && cfg.anonKey) {
                const exchangeRes = await fetch(`${cfg.supabaseUrl}/auth/v1/token?grant_type=pkce`, {
                  method: 'POST',
                  headers: {
                    apikey: cfg.anonKey,
                    'Content-Type': 'application/json'
                  },
                  body: JSON.stringify({
                    auth_code: authCode,
                    code_verifier: codeVerifier.split('/')[0]
                  })
                });
                if (exchangeRes.ok) {
                  const exchangeData = await exchangeRes.json();
                  session = {
                    access_token: exchangeData.access_token,
                    refresh_token: exchangeData.refresh_token,
                    expires_at: Math.floor(Date.now() / 1000) + (exchangeData.expires_in || 3600),
                    token_type: exchangeData.token_type || 'bearer',
                    user: exchangeData.user
                  };
                  user = exchangeData.user;
                }
              }
            }

            // Clean address bar AFTER code exchange attempt, preserving slug and other non-auth parameters
            searchParams.delete('code');
            searchParams.delete('state');
            searchParams.delete('sb_flow_id');
            const remaining = searchParams.toString();
            const cleanUrl = window.location.pathname + (remaining ? `?${remaining}` : '') + (window.location.hash || '');
            window.history.replaceState({}, document.title, cleanUrl);

            if (session) {
              this.session = session;
              localStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(session));

              const displayName = user?.user_metadata?.full_name || user?.user_metadata?.name || user?.email || 'Reader';
              this.showToast(`Signed in successfully as ${this.escape(displayName)}.`, 'success');

              this.syncAuthStateAcrossUI();
              this.dispatchAuthChangeEvent(session);

              // Restore scroll position if saved
              try {
                const savedScroll = sessionStorage.getItem('gct_oauth_scroll_y');
                if (savedScroll) {
                  const scrollY = parseInt(savedScroll, 10);
                  if (!isNaN(scrollY) && scrollY > 0) {
                    window.scrollTo({ top: scrollY, behavior: 'smooth' });
                  }
                }
              } catch {}

              // Check if we need to return to a different stored page context
              try {
                const storedReturn = sessionStorage.getItem('gct_oauth_return_url');
                sessionStorage.removeItem('gct_oauth_return_url');
                sessionStorage.removeItem('gct_oauth_scroll_y');

                if (storedReturn) {
                  const validatedReturn = this.buildValidatedRedirectUrl(storedReturn);
                  const currentNormalized = window.location.href.split('#')[0].split('?')[0];
                  const targetNormalized = validatedReturn.split('#')[0].split('?')[0];

                  if (currentNormalized !== targetNormalized && !currentNormalized.endsWith(targetNormalized)) {
                    window.location.href = validatedReturn;
                    return;
                  }
                }
              } catch {}
              return;
            }
          } catch (err) {
            console.warn('[GCT Auth] Error processing PKCE callback:', err);
            this.showToast('Unable to complete PKCE authentication. Please try again.', 'error');
          } finally {
            this._isExchangingCode = false;
          }
          return;
        }
      }

      // 3. Parse Supabase Auth Implicit Grant Hash: #access_token=...&refresh_token=...&expires_at=...
      if (hash && hash.includes('access_token=') && hash.includes('refresh_token=')) {
        try {
          const params = new URLSearchParams(hash.substring(1));
          const accessToken = params.get('access_token');
          const refreshToken = params.get('refresh_token');
          const expiresIn = parseInt(params.get('expires_in') || '3600', 10);
          const tokenType = params.get('token_type') || 'bearer';

          if (accessToken) {
            const expiresAt = Math.floor(Date.now() / 1000) + expiresIn;

            // Fetch User Details from Supabase Auth
            const cfg = window.__GCT_CONFIG__ || {};
            const userRes = await fetch(`${cfg.supabaseUrl}/auth/v1/user`, {
              headers: {
                apikey: cfg.anonKey,
                Authorization: `Bearer ${accessToken}`
              }
            });

            if (userRes.ok) {
              const user = await userRes.json();
              this.session = {
                access_token: accessToken,
                refresh_token: refreshToken,
                expires_at: expiresAt,
                token_type: tokenType,
                user: user
              };
              localStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(this.session));

              // Clean address bar without refresh and preserving existing query parameters (like ?slug=...)
              const cleanUrl = window.location.pathname + window.location.search;
              window.history.replaceState({}, document.title, cleanUrl);

              const displayName = user.user_metadata?.full_name || user.email;
              this.showToast(`Signed in successfully as ${this.escape(displayName)}.`, 'success');

              this.syncAuthStateAcrossUI();
              this.dispatchAuthChangeEvent(this.session);

              // Restore scroll position if saved
              try {
                const savedScroll = sessionStorage.getItem('gct_oauth_scroll_y');
                if (savedScroll) {
                  const scrollY = parseInt(savedScroll, 10);
                  if (!isNaN(scrollY) && scrollY > 0) {
                    window.scrollTo({ top: scrollY, behavior: 'smooth' });
                  }
                }
              } catch {}

              // Check if we need to return to a different stored page context
              try {
                const storedReturn = sessionStorage.getItem('gct_oauth_return_url');
                sessionStorage.removeItem('gct_oauth_return_url');
                sessionStorage.removeItem('gct_oauth_scroll_y');

                if (storedReturn) {
                  const validatedReturn = this.buildValidatedRedirectUrl(storedReturn);
                  const currentNormalized = window.location.href.split('#')[0];
                  const targetNormalized = validatedReturn.split('#')[0];

                  // Only navigate if target is genuinely a different page
                  if (currentNormalized !== targetNormalized && !currentNormalized.endsWith(targetNormalized)) {
                    window.location.href = validatedReturn;
                    return;
                  }
                }
              } catch {}

            } else {
              // Expired or invalid token response from server
              console.warn('[GCT Auth] Supabase /auth/v1/user rejected access token (HTTP ' + userRes.status + ')');
              this.showToast('Authentication session expired or invalid. Please sign in again.', 'warning');
              const cleanUrl = window.location.pathname + window.location.search;
              window.history.replaceState({}, document.title, cleanUrl);
            }
          }
        } catch (err) {
          console.warn('[GCT Auth] OAuth callback processing error:', err);
          this.showToast('Unable to complete authentication. Please try again.', 'error');
        }
      }
    }

    isTrustedGoogleAvatarUrl(urlStr) {
      if (!urlStr || typeof urlStr !== 'string') return false;
      try {
        const parsed = new URL(urlStr);
        if (parsed.protocol !== 'https:') return false;
        const host = parsed.hostname.toLowerCase();
        return host === 'googleusercontent.com' || host.endsWith('.googleusercontent.com');
      } catch {
        return false;
      }
    }

    getTrustedGoogleAvatarUrl(user) {
      if (!user) return null;
      const meta = user.user_metadata || {};
      const candidates = [
        meta.avatar_url,
        meta.picture
      ];
      if (Array.isArray(user.identities)) {
        const googleIdentity = user.identities.find(i => i.provider === 'google');
        if (googleIdentity?.identity_data) {
          candidates.push(googleIdentity.identity_data.avatar_url);
          candidates.push(googleIdentity.identity_data.picture);
        }
      }
      for (const candidate of candidates) {
        if (typeof candidate === 'string' && this.isTrustedGoogleAvatarUrl(candidate)) {
          return candidate;
        }
      }
      return null;
    }

    getIdentity() {
      if (this.session && this.session.user) {
        const u = this.session.user;
        const meta = u.user_metadata || {};
        const fullName = meta.full_name || meta.name || u.email?.split('@')[0] || 'Authenticated Reader';
        const firstName = meta.given_name || fullName.split(' ')[0] || 'Reader';

        const safeAvatarUrl = this.getTrustedGoogleAvatarUrl(u);

        return {
          isAuthenticated: true,
          isGuest: false,
          userId: u.id,
          email: u.email || '',
          workEmail: u.email || '',
          displayName: this.escape(fullName),
          firstName: this.escape(firstName),
          avatarUrl: safeAvatarUrl,
          provider: u.app_metadata?.provider || 'google'
        };
      }

      return {
        isAuthenticated: false,
        isGuest: true,
        userId: this.guest?.id || 'guest',
        guestSecret: this.guest?.secret || '',
        email: this.guest?.email || '',
        workEmail: this.guest?.email || '',
        displayName: this.escape(this.guest?.name || 'Guest Reader'),
        firstName: this.escape((this.guest?.name || 'Guest').split(' ')[0] || 'Guest'),
        avatarUrl: null,
        provider: 'guest'
      };
    }

    async getValidatedIdentity() {
      // Always consult Supabase SDK session first if available
      if (this.supabase && this.supabase.auth && typeof this.supabase.auth.getSession === 'function') {
        try {
          const { data, error } = await this.supabase.auth.getSession();
          if (data && data.session) {
            this.session = data.session;
            return this.getIdentity();
          }
        } catch (sdkErr) {
          console.warn('[GCT Auth] SDK getSession refresh notice:', sdkErr);
        }
      }

      // Validate or refresh session against Supabase Auth
      if (this.session) {
        const nowSec = Math.floor(Date.now() / 1000);
        // If expired or expiring within 30 seconds
        if (this.session.expires_at && (this.session.expires_at - nowSec <= 30)) {
          if (this.session.refresh_token) {
            const cfg = window.__GCT_CONFIG__ || {};
            if (cfg.supabaseUrl && cfg.anonKey) {
              try {
                const refreshRes = await fetch(`${cfg.supabaseUrl}/auth/v1/token?grant_type=refresh_token`, {
                  method: 'POST',
                  headers: {
                    apikey: cfg.anonKey,
                    'Content-Type': 'application/json'
                  },
                  body: JSON.stringify({ refresh_token: this.session.refresh_token })
                });

                if (refreshRes.ok) {
                  const data = await refreshRes.json();
                  this.session.access_token = data.access_token;
                  this.session.refresh_token = data.refresh_token;
                  this.session.expires_at = Math.floor(Date.now() / 1000) + data.expires_in;
                  if (data.user) this.session.user = data.user;
                  localStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(this.session));
                  this.syncAuthStateAcrossUI();
                  return this.getIdentity();
                } else {
                  console.warn('[GCT Auth] Session refresh rejected, falling back to guest');
                  localStorage.removeItem(STORAGE_KEYS.SESSION);
                  this.session = null;
                  this.syncAuthStateAcrossUI();
                }
              } catch (err) {
                console.warn('[GCT Auth] Session refresh network error:', err);
              }
            }
          } else {
            localStorage.removeItem(STORAGE_KEYS.SESSION);
            this.session = null;
            this.syncAuthStateAcrossUI();
          }
        } else {
          return this.getIdentity();
        }
      }

      return this.getIdentity();
    }

    /* -------------------------------------------------------------------------
     * 2. GOOGLE OAUTH FLOW & REDIRECT DESTINATION VALIDATION
     * ---------------------------------------------------------------------- */
    buildValidatedRedirectUrl(rawCandidateUrl) {
      try {
        if (!rawCandidateUrl || typeof rawCandidateUrl !== 'string') {
          return window.location.href;
        }

        const trimmed = rawCandidateUrl.trim();
        // Reject protocol-relative URLs (//evil.com), javascript:, data:, vbscript:
        if (trimmed.startsWith('//') || trimmed.toLowerCase().startsWith('javascript:') || trimmed.toLowerCase().startsWith('data:')) {
          console.warn('[GCT Auth] Unsafe redirect URL pattern rejected:', rawCandidateUrl);
          return window.location.href;
        }

        // 1. Resolve relative URLs against current page URL
        const resolved = new URL(trimmed, window.location.href);

        // 2. Validate approved origin and transport security
        const currentHost = window.location.hostname.toLowerCase();
        const isLocalEnv = currentHost === '127.0.0.1' || currentHost === 'localhost';

        if (isLocalEnv) {
          // Local development: strictly limit to loopback origins
          if (resolved.hostname !== '127.0.0.1' && resolved.hostname !== 'localhost') {
            console.warn('[GCT Auth] External redirect rejected in local development:', resolved.href);
            return window.location.href;
          }
        } else {
          // Production: Strictly enforce HTTPS and approved Blog origin
          const approvedDomain = 'blog.greycircuit.tech';
          if (resolved.protocol !== 'https:' || resolved.hostname.toLowerCase() !== approvedDomain) {
            console.warn('[GCT Auth] Insecure or external redirect rejected in production:', resolved.href);
            const safeFallback = new URL(resolved.pathname + resolved.search, `https://${approvedDomain}`);
            return safeFallback.href;
          }
        }

        // Return verified absolute URL preserving pathname and query parameters
        return resolved.href;
      } catch (err) {
        console.warn('[GCT Auth] Error validating redirect URL, falling back to current location:', err);
        return window.location.href;
      }
    }

    async signInWithGoogle(customReturnUrl) {
      const cfg = window.__GCT_CONFIG__ || {};
      if (!cfg.supabaseUrl || !cfg.anonKey) {
        this.showToast('Supabase client endpoint configuration is missing.', 'error');
        return;
      }

      const googleProv = AUTH_PROVIDERS_CONFIG.find(p => p.id === 'google');
      if (googleProv && googleProv.backendEnabled === false) {
        this.showToast('Google OAuth is not currently enabled in the database environment.', 'warning');
        return;
      }

      // Compute and validate absolute return destination
      const returnUrl = this.buildValidatedRedirectUrl(customReturnUrl || window.location.href);

      // Store return context and current scroll position
      try {
        sessionStorage.setItem('gct_oauth_return_url', returnUrl);
        sessionStorage.setItem('gct_oauth_scroll_y', String(window.scrollY || 0));
      } catch {}

      // If current user is an anonymous user, link identity seamlessly to preserve interactions
      if (this.session?.user?.is_anonymous && typeof this.supabase?.auth?.linkIdentity === 'function') {
        try {
          console.log('[GCT Auth] Upgrading anonymous reader account with Google OAuth via linkIdentity()...');
          const { data: linkData, error: linkErr } = await this.supabase.auth.linkIdentity({
            provider: 'google',
            options: {
              redirectTo: returnUrl
            }
          });
          if (!linkErr && linkData?.url) {
            window.location.href = linkData.url;
            return;
          }
        } catch (linkEx) {
          console.warn('[GCT Auth] linkIdentity notice, falling back to standard signInWithOAuth:', linkEx);
        }
      }

      // If Supabase client is initialized, use PKCE signInWithOAuth
      if (this.supabase && this.supabase.auth && typeof this.supabase.auth.signInWithOAuth === 'function') {
        try {
          const { data, error } = await this.supabase.auth.signInWithOAuth({
            provider: 'google',
            options: {
              redirectTo: returnUrl,
              queryParams: {
                access_type: 'offline',
                prompt: 'consent'
              }
            }
          });
          if (error) {
            console.error('[GCT Auth] PKCE signInWithOAuth error:', error);
            this.showToast(`OAuth sign-in failed: ${error.message}`, 'error');
            return;
          }
          if (data?.url) {
            window.location.href = data.url;
            return;
          }
        } catch (oauthErr) {
          console.warn('[GCT Auth] Error during signInWithOAuth, falling back to direct authorize endpoint:', oauthErr);
        }
      }

      // Fallback: Direct endpoint if Supabase JS client is unavailable
      const authEndpoint = `${cfg.supabaseUrl}/auth/v1/authorize?provider=google&redirect_to=${encodeURIComponent(returnUrl)}`;
      window.location.href = authEndpoint;
    }

    async signOut() {
      try {
        if (this.supabase && this.supabase.auth && typeof this.supabase.auth.signOut === 'function') {
          try {
            await this.supabase.auth.signOut();
          } catch (sdkSignOutErr) {
            console.warn('[GCT Auth] SDK signOut warning:', sdkSignOutErr);
          }
        }
        localStorage.removeItem(STORAGE_KEYS.SESSION);
        localStorage.removeItem(STORAGE_KEYS.PROFILE_DRAFT);
        localStorage.removeItem('gct_reader_bio');
        this.session = null;
        this.profile = null;
        this._lastKnownCloudUpdatedAt = null;
        this.syncAuthStateAcrossUI();
        this.dispatchAuthChangeEvent(null);
        this.showToast('Signed out. You are now participating in Guest Mode.', 'info');

        // If on profile page, re-render guest view immediately without forcing a jarring hard reload
        const currentPath = (typeof window !== 'undefined' && window.location?.pathname) || '';
        const isProfilePage = currentPath.endsWith('profile.html') ||
                              Boolean(document.getElementById('profile-guest-view'));
        if (isProfilePage) {
          this.initProfilePage();
        } else {
          setTimeout(() => window.location.reload(), 800);
        }
      } catch (err) {
        console.error('[GCT Auth] Sign out error:', err);
      }
    }

    dispatchAuthChangeEvent(session) {
      try {
        const ident = this.getIdentity();
        window.dispatchEvent(new CustomEvent('gct:auth-state-changed', {
          detail: { session, identity: ident }
        }));
      } catch (e) {
        console.warn('[GCT Auth] dispatchAuthChangeEvent notice:', e);
      }
    }

    syncAuthStateAcrossUI() {
      // 1. Always update stationary nav widget
      this.renderNavWidget();

      // 2. If on profile page, update profile views
      const currentPath = (typeof window !== 'undefined' && window.location?.pathname) || '';
      const isProfilePage = currentPath.endsWith('profile.html') ||
                            Boolean(document.getElementById('profile-authenticated-view'));
      if (isProfilePage && typeof this.initProfilePage === 'function') {
        this.initProfilePage();
      }

      // 3. If profile modal is open, re-render modal content
      const modal = document.getElementById('reader-profile-modal');
      if (modal && modal.classList && typeof modal.classList.contains === 'function' && modal.classList.contains('is-open')) {
        this.populateModalFields();
        this.renderAuthProviders();
      }

      // 4. If comment form exists, prefill name and email for authenticated user
      const commentNameInput = document.getElementById('comment-author-name');
      const commentEmailInput = document.getElementById('comment-author-email');
      if (commentNameInput || commentEmailInput) {
        const ident = this.getIdentity();
        if (ident.isAuthenticated) {
          if (commentNameInput && !commentNameInput.value) commentNameInput.value = ident.displayName;
          if (commentEmailInput && !commentEmailInput.value) commentEmailInput.value = ident.email;
        }
      }
    }

    /* -------------------------------------------------------------------------
     * 3. NAVIGATION WIDGET RENDERING & EXPANDING GREETING
     * ---------------------------------------------------------------------- */
    renderNavWidget() {
      const ident = this.getIdentity();
      const prefixEl = document.getElementById('greeting-prefix');
      const nameEl = document.getElementById('greeting-name');
      const avatarWrap = document.getElementById('profile-avatar-wrap');

      if (prefixEl) prefixEl.textContent = 'Hi,';
      if (nameEl) nameEl.textContent = `${ident.firstName}.`;

      if (avatarWrap) {
        if (ident.isAuthenticated && ident.avatarUrl && this.isTrustedGoogleAvatarUrl(ident.avatarUrl)) {
          const initials = (ident.displayName || 'Reader').split(' ').map(n => n[0]).slice(0, 2).join('').toUpperCase();
          avatarWrap.innerHTML = `<img src="${this.escape(ident.avatarUrl)}" alt="${this.escape(ident.displayName)}" class="nav-user-avatar-img" onerror="this.onerror=null; this.parentElement.innerHTML='<span class=\\'nav-avatar-initials font-jetbrains\\' style=\\'font-size: 13px; font-weight: 700;\\'>${this.escape(initials)}</span>';" />`;
        } else if (ident.isAuthenticated) {
          const initials = (ident.displayName || 'Reader').split(' ').map(n => n[0]).slice(0, 2).join('').toUpperCase();
          avatarWrap.innerHTML = `<span class="nav-avatar-initials font-jetbrains" style="font-size: 13px; font-weight: 700;">${this.escape(initials)}</span>`;
        } else {
          avatarWrap.innerHTML = `
            <svg class="profile-avatar-svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
              <circle cx="12" cy="7" r="4"></circle>
            </svg>
          `;
        }
      }

      this.alignProfileWidget();
    }

    alignProfileWidget() {
      const nav = document.getElementById('site-nav');
      const widget = document.getElementById('reader-profile-widget');
      if (!nav || !widget) return;
      if (typeof nav.getBoundingClientRect !== 'function') return;

      const rect = nav.getBoundingClientRect();
      const isMobile = window.innerWidth <= 820;
      const navHeight = isMobile ? 52 : (Math.round(rect.height) || 64);
      const navWidth = Math.round(rect.width) || (isMobile ? window.innerWidth - 84 : 560);

      document.documentElement.style.setProperty('--nav-bar-h', `${navHeight}px`);
      document.documentElement.style.setProperty('--nav-bar-w', `${navWidth}px`);

      if (nav.classList.contains('is-scrolled')) {
        widget.classList.add('is-scrolled');
      } else {
        widget.classList.remove('is-scrolled');
      }

      if (nav.classList.contains('is-hidden')) {
        widget.classList.add('is-hidden');
      } else {
        widget.classList.remove('is-hidden');
      }

      if (!isMobile) {
        const idealLeft = rect.right + 10;
        const maxLeft = window.innerWidth - navHeight - 14;
        widget.style.left = `${Math.min(idealLeft, maxLeft)}px`;
        widget.style.right = 'auto';
        widget.style.top = '';
      } else {
        widget.style.left = '';
        widget.style.right = '';
        widget.style.top = '';
      }
    }

    /* -------------------------------------------------------------------------
     * 4. READER PROFILE & SETTINGS MODAL CONTROLLER
     * ---------------------------------------------------------------------- */
    openProfileModal() {
      const modal = document.getElementById('reader-profile-modal');
      const backdrop = document.getElementById('reader-profile-backdrop');
      if (!modal) return;

      const ident = this.getIdentity();

      // Populate Modal Fields
      const nameInp = document.getElementById('modal-profile-name');
      const emailInp = document.getElementById('modal-profile-email');
      const bioInp = document.getElementById('modal-profile-bio');
      const authModeBadge = document.getElementById('modal-auth-mode-badge');
      const guestNotice = document.getElementById('modal-guest-notice');

      if (nameInp) nameInp.value = ident.displayName;
      if (emailInp) emailInp.value = ident.email || (ident.isGuest ? 'Not provided (session only)' : '');
      if (bioInp) bioInp.value = localStorage.getItem('gct_reader_bio') || '';

      if (ident.isAuthenticated) {
        if (authModeBadge) {
          authModeBadge.textContent = 'Google Verified';
          authModeBadge.className = 'badge bg-success font-jetbrains';
        }
        if (guestNotice) guestNotice.style.display = 'none';
      } else {
        if (authModeBadge) {
          authModeBadge.textContent = 'Guest Mode';
          authModeBadge.className = 'badge bg-secondary font-jetbrains';
        }
        if (guestNotice) guestNotice.style.display = 'block';
      }

      this.renderEngagementHistory();
      this.renderAuthProviders();

      modal.classList.add('is-open');
      if (backdrop) backdrop.classList.add('is-open');
      modal.setAttribute('aria-hidden', 'false');
    }

    renderAuthProviders() {
      const container = document.getElementById('modal-identity-providers-list');
      if (!container) return;

      const ident = this.getIdentity();

      if (ident.isAuthenticated) {
        const currentProviderId = ident.provider || 'google';
        const provConfig = AUTH_PROVIDERS_CONFIG.find(p => p.id === currentProviderId) || {
          name: currentProviderId.charAt(0).toUpperCase() + currentProviderId.slice(1),
          iconSvg: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="m9 12 2 2 4-4"></path></svg>`
        };

        container.innerHTML = `
          <div class="auth-provider-card auth-provider-connected">
            <div class="d-flex align-items-center gap-2">
              <span class="provider-icon-wrap" style="display:flex; align-items:center;">${provConfig.iconSvg}</span>
              <div>
                <div class="auth-provider-title font-jetbrains" style="font-size: 12px; font-weight: 600; color: #fff;">${provConfig.name} Account</div>
                <div class="auth-provider-status font-mono" style="font-size: 10px; color: #34d399;">Connected as ${this.escape(ident.email || ident.displayName)}</div>
              </div>
            </div>
            <button type="button" class="btn btn-secondary btn-sm font-jetbrains btn-provider-disconnect" style="font-size: 11px; padding: 5px 12px; color: #fca5a5; border-color: rgba(239,68,68,0.3); background: rgba(239,68,68,0.08);">
              Disconnect
            </button>
          </div>
        `;

        container.querySelector('.btn-provider-disconnect')?.addEventListener('click', () => {
          this.signOut();
        });
      } else {
        container.innerHTML = AUTH_PROVIDERS_CONFIG.map(prov => {
          const isConfigured = prov.enabled && prov.checkConfigured();
          if (isConfigured) {
            return `
              <div class="auth-provider-card">
                <div class="d-flex align-items-center gap-2">
                  <span class="provider-icon-wrap" style="display:flex; align-items:center;">${prov.iconSvg}</span>
                  <div>
                    <div class="auth-provider-title font-jetbrains" style="font-size: 12px; font-weight: 600; color: #fff;">${prov.name}</div>
                    <div class="auth-provider-status font-jetbrains" style="font-size: 10px; color: #a1a1aa;">Sign in to sync your comments and profile across devices</div>
                  </div>
                </div>
                <button type="button" class="auth-provider-btn font-jetbrains btn-provider-connect" data-provider="${prov.id}">
                  Continue with ${prov.name} ↗
                </button>
              </div>
            `;
          } else {
            return `
              <div class="auth-provider-card auth-provider-disabled" style="opacity: 0.6;">
                <div class="d-flex align-items-center gap-2">
                  <span class="provider-icon-wrap" style="display:flex; align-items:center;">${prov.iconSvg}</span>
                  <div>
                    <div class="auth-provider-title font-jetbrains" style="font-size: 12px; font-weight: 600; color: #a1a1aa;">${prov.name}</div>
                    <div class="auth-provider-status font-jetbrains" style="font-size: 10px; color: #71717a;">OAuth provider unavailable</div>
                  </div>
                </div>
                <span class="badge bg-secondary font-jetbrains" style="font-size: 10px; background: rgba(255,255,255,0.08) !important; color: #71717a;">Unavailable</span>
              </div>
            `;
          }
        }).join('');

        container.querySelectorAll('.btn-provider-connect').forEach(btn => {
          btn.addEventListener('click', () => {
            const pid = btn.getAttribute('data-provider');
            const prov = AUTH_PROVIDERS_CONFIG.find(p => p.id === pid);
            if (prov && typeof prov.action === 'function') {
              prov.action(this);
            }
          });
        });
      }
    }

    closeProfileModal() {
      const modal = document.getElementById('reader-profile-modal');
      const backdrop = document.getElementById('reader-profile-backdrop');
      if (modal) {
        modal.classList.remove('is-open');
        modal.setAttribute('aria-hidden', 'true');
      }
      if (backdrop) backdrop.classList.remove('is-open');
    }

    async saveProfile() {
      if (this._isSavingProfile) {
        console.warn('[GCT Auth] Modal save already in progress, ignoring duplicate submission.');
        return;
      }
      this._isSavingProfile = true;

      try {
        const nameInp = document.getElementById('modal-profile-name');
        const bioInp = document.getElementById('modal-profile-bio');

        const newName = nameInp?.value.trim();
        const newBio = bioInp?.value.trim() || '';

        if (!newName) {
          this.showToast('Display name cannot be empty.', 'error');
          return;
        }
        if (newName.length > 100) {
          this.showToast('Display name cannot exceed 100 characters.', 'error');
          return;
        }
        if (newBio.length > 250) {
          this.showToast('Biography cannot exceed 250 characters.', 'error');
          return;
        }

        if (this.session?.user) {
          const nowSec = Math.floor(Date.now() / 1000);
          if (this.session.expires_at && (this.session.expires_at <= nowSec)) {
            this.saveProfileDraftSafely(this.session.user.id, newName, newBio, 'session_expired');
            this.showToast('Your session has expired. Please sign in again to save changes.', 'error');
            return;
          }

          let dbPersisted = false;
          let dbErrorMessage = null;
          let conflictDetected = false;

          if (this.supabase && this.session.user.id) {
            try {
              const nowIso = new Date().toISOString();

              // Pre-check if _lastKnownCloudUpdatedAt is not yet cached
              if (!this._lastKnownCloudUpdatedAt) {
                const { data: cloudRow } = await this.supabase
                  .from('profiles')
                  .select('id, updated_at')
                  .eq('id', this.session.user.id)
                  .maybeSingle();
                if (cloudRow?.updated_at) {
                  this._lastKnownCloudUpdatedAt = cloudRow.updated_at;
                }
              }

              let dbErr = null;

              if (this._lastKnownCloudUpdatedAt) {
                // ATOMIC CONDITIONAL OCC UPDATE
                // PostgREST translates this to UPDATE public.profiles SET ... WHERE id = $1 AND updated_at = $2 RETURNING id, updated_at
                const { data: updatedRows, error: updateErr } = await this.supabase
                  .from('profiles')
                  .update({
                    display_name: newName,
                    bio: newBio,
                    updated_at: nowIso
                  })
                  .eq('id', this.session.user.id)
                  .eq('updated_at', this._lastKnownCloudUpdatedAt)
                  .select('id, updated_at');

                if (updateErr) {
                  dbErr = updateErr;
                } else if (!updatedRows || updatedRows.length === 0) {
                  // Zero rows updated: Check if row exists (OCC conflict) or was deleted
                  const { data: existingRow } = await this.supabase
                    .from('profiles')
                    .select('id, updated_at')
                    .eq('id', this.session.user.id)
                    .maybeSingle();

                  if (existingRow) {
                    conflictDetected = true;
                    dbErrorMessage = 'Cloud conflict: Your profile was modified in another session. Please reload to review the latest changes.';
                  } else {
                    const { error: insertErr } = await this.supabase
                      .from('profiles')
                      .insert({
                        id: this.session.user.id,
                        display_name: newName,
                        bio: newBio,
                        updated_at: nowIso
                      });
                    if (insertErr) {
                      dbErr = insertErr;
                    } else {
                      dbPersisted = true;
                      this._lastKnownCloudUpdatedAt = nowIso;
                    }
                  }
                } else {
                  dbPersisted = true;
                  this._lastKnownCloudUpdatedAt = updatedRows[0].updated_at || nowIso;
                }
              } else {
                // No prior row in cloud: attempt insert
                const { error: insertErr } = await this.supabase
                  .from('profiles')
                  .insert({
                    id: this.session.user.id,
                    display_name: newName,
                    bio: newBio,
                    updated_at: nowIso
                  });
                if (insertErr) {
                  if (insertErr.code === '23505') {
                    conflictDetected = true;
                    dbErrorMessage = 'Cloud conflict: Your profile was created in another session. Please reload to review latest changes.';
                  } else {
                    dbErr = insertErr;
                  }
                } else {
                  dbPersisted = true;
                  this._lastKnownCloudUpdatedAt = nowIso;
                }
              }

              if (dbErr) {
                console.error('[GCT Auth] Modal profile db upsert error:', {
                  code: dbErr.code,
                  message: dbErr.message,
                  status: dbErr.status || dbErr.statusCode
                });
                if (dbErr.code === '42501' || dbErr.status === 401 || dbErr.status === 403) {
                  dbErrorMessage = 'Access denied: Database security policy prevented saving your profile.';
                } else {
                  dbErrorMessage = `Database error (${dbErr.code || 'sync_failed'}): ${dbErr.message || 'Unable to persist profile.'}`;
                }
              } else if (dbPersisted) {
                this.profile = {
                  ...(this.profile || {}),
                  id: this.session.user.id,
                  display_name: newName,
                  bio: newBio,
                  updated_at: this._lastKnownCloudUpdatedAt || nowIso
                };
              }
            } catch (dbEx) {
              console.error('[GCT Auth] Modal profile db upsert exception:', { message: dbEx?.message });
              dbErrorMessage = 'Network error: Unable to connect to database. Changes not saved.';
            }
          } else {
            dbErrorMessage = 'Database client is not available.';
          }

          if (dbPersisted) {
            try {
              localStorage.setItem('gct_reader_bio', newBio);
              localStorage.removeItem(STORAGE_KEYS.PROFILE_DRAFT);
            } catch {}

            this.session.user.user_metadata = this.session.user.user_metadata || {};
            this.session.user.user_metadata.full_name = newName;
            this.session.user.user_metadata.bio = newBio;
            localStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(this.session));

            const cfg = window.__GCT_CONFIG__ || {};
            if (this.session?.access_token && cfg.supabaseUrl && cfg.anonKey) {
              try {
                await fetch(`${cfg.supabaseUrl}/auth/v1/user`, {
                  method: 'PUT',
                  headers: {
                    apikey: cfg.anonKey,
                    Authorization: `Bearer ${this.session.access_token}`,
                    'Content-Type': 'application/json'
                  },
                  body: JSON.stringify({
                    data: { full_name: newName, bio: newBio }
                  })
                });
              } catch {}
            }

            this.renderNavWidget();
            this.showToast('Profile saved directly to database.', 'success');
            this.closeProfileModal();
          } else {
            this.saveProfileDraftSafely(this.session.user.id, newName, newBio, conflictDetected ? 'cloud_conflict' : dbErrorMessage);
            this.showToast(dbErrorMessage || 'Database synchronization failed. Changes not saved.', 'error');
          }
        } else {
          if (this.guest) {
            this.guest.name = newName;
            localStorage.setItem('gct_guest_saved_name', newName);
          }
          if (newBio) localStorage.setItem('gct_reader_bio', newBio);
          this.renderNavWidget();
          this.showToast('Guest profile preferences updated.', 'success');
          this.closeProfileModal();
        }
      } finally {
        this._isSavingProfile = false;
      }
    }

    renderEngagementHistory() {
      const container = document.getElementById('modal-engagement-history');
      if (!container) return;

      const comments = JSON.parse(localStorage.getItem('gct_user_comments_history') || '[]');

      const likedArticles = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith('gct_liked_art_') && localStorage.getItem(key) === 'true') {
          likedArticles.push(key.replace('gct_liked_art_', ''));
        }
      }

      if (comments.length === 0 && likedArticles.length === 0) {
        container.innerHTML = `
          <div class="empty-engagement-history font-jetbrains">
            No comments, replies, or article likes recorded in this session. Engage with technical publications to build your activity history.
          </div>
        `;
        return;
      }

      let html = '';
      comments.forEach(item => {
        const isReply = !!item.isReply;
        const pubUrl = item.articleSlug ? `article.html?slug=${encodeURIComponent(item.articleSlug)}` : 'index.html';
        const pubTitle = item.articleTitle || 'Publication';

        html += `
          <div class="engagement-history-row" style="padding: 10px 14px; margin-bottom: 8px; background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06); border-radius: 6px;">
            <div class="d-flex justify-content-between align-items-center mb-1">
              <span class="font-mono text-2xs text-muted">${new Date(item.timestamp).toLocaleDateString()}</span>
              <div class="d-flex align-items-center gap-2">
                <span class="badge ${isReply ? 'bg-info' : 'bg-primary'} font-jetbrains" style="font-size: 10px;">${isReply ? 'Reply' : 'Comment'}</span>
                <a href="${pubUrl}" class="font-jetbrains text-2xs text-muted" style="color: #c4b5fd; text-decoration: none;">${this.escape(pubTitle)} →</a>
              </div>
            </div>
            <div class="small text-light text-truncate" style="max-width: 600px;">${this.escape(item.content)}</div>
          </div>
        `;
      });

      likedArticles.forEach(artId => {
        html += `
          <div class="engagement-history-row" style="padding: 10px 14px; margin-bottom: 8px; background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06); border-radius: 6px;">
            <div class="d-flex justify-content-between align-items-center">
              <span class="badge bg-secondary font-jetbrains" style="font-size: 10px; background: rgba(124,58,237,0.2) !important; color: #c4b5fd;">Article Liked</span>
              <a href="index.html" class="font-jetbrains text-2xs" style="color: #c4b5fd; text-decoration: none;">View Catalog →</a>
            </div>
          </div>
        `;
      });

      container.innerHTML = html;
    }

    exportPersonalData() {
      const ident = this.getIdentity();
      const comments = JSON.parse(localStorage.getItem('gct_user_comments_history') || '[]');
      const consent = JSON.parse(localStorage.getItem(STORAGE_KEYS.CONSENT) || '{}');

      const exportBundle = {
        entity: 'GREYCIRCUIT TECHNOLOGIES PRIVATE LIMITED',
        export_date: new Date().toISOString(),
        reader_identity: ident,
        consent_record: consent,
        comments_and_replies: comments,
        privacy_framework: 'DPDP Act 2023 / GDPR Export'
      };

      const blob = new Blob([JSON.stringify(exportBundle, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `gct-reader-data-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      this.showToast('Personal data export downloaded.', 'success');
    }

    async deleteAccount() {
      if (confirm('Are you sure you want to delete your reader identity and clear all local engagement data? This action is irreversible.')) {
        // 1. If authenticated, revoke active session on Supabase Auth server
        if (this.session?.access_token) {
          const cfg = window.__GCT_CONFIG__ || {};
          if (cfg.supabaseUrl && cfg.anonKey) {
            try {
              await fetch(`${cfg.supabaseUrl}/auth/v1/logout`, {
                method: 'POST',
                headers: {
                  apikey: cfg.anonKey,
                  Authorization: `Bearer ${this.session.access_token}`
                }
              });
            } catch (err) {
              console.warn('[GCT Auth] Remote session revocation error:', err);
            }
          }
        }

        // 2. Comprehensive LocalStorage Purge across all GCT reader keys
        const keysToRemove = [];
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (key && (key.startsWith('gct_') || key.startsWith('supabase.'))) {
            keysToRemove.push(key);
          }
        }
        keysToRemove.forEach(k => localStorage.removeItem(k));

        // 3. Explicit fallback for core storage keys
        localStorage.removeItem(STORAGE_KEYS.SESSION);
        localStorage.removeItem(STORAGE_KEYS.GUEST_ID);
        localStorage.removeItem(STORAGE_KEYS.GUEST_SECRET);
        localStorage.removeItem('gct_user_comments_history');
        localStorage.removeItem(STORAGE_KEYS.PROFILE_DRAFT);
        localStorage.removeItem('gct_reader_bio');
        localStorage.removeItem('gct_guest_saved_name');
        localStorage.removeItem('gct_user_fp');
        localStorage.removeItem(STORAGE_KEYS.CONSENT);

        this.session = null;
        this.guest = null;

        this.showToast('Reader account and local session data purged.', 'info');
        setTimeout(() => window.location.reload(), 1000);
      }
    }

    /* -------------------------------------------------------------------------
     * 5. PRIVACY & COOKIE CONSENT BANNER CONTROLLER
     * ---------------------------------------------------------------------- */
    getConsent() {
      try {
        const raw = localStorage.getItem(STORAGE_KEYS.CONSENT);
        return raw ? JSON.parse(raw) : null;
      } catch (e) {
        return null;
      }
    }

    initConsentBanner() {
      const consent = localStorage.getItem(STORAGE_KEYS.CONSENT);
      const banner = document.getElementById('privacy-consent-banner');
      if (!consent && banner && banner.style) {
        banner.style.display = 'block';
      }
    }

    saveConsent(choice, customCategories = null) {
      const record = {
        consent_id: 'c_' + Date.now().toString(36),
        timestamp: new Date().toISOString(),
        version: 'v2026.1',
        choice: choice,
        categories: customCategories || {
          essential: true,
          preferences: choice === 'accept_all',
          analytics: choice === 'accept_all',
          marketing: false
        }
      };

      localStorage.setItem(STORAGE_KEYS.CONSENT, JSON.stringify(record));
      const banner = document.getElementById('privacy-consent-banner');
      if (banner) banner.style.display = 'none';

      this.closeCookiePreferences();

      this.showToast('Privacy preferences saved.', 'success');
    }

    openCookiePreferences() {
      const modal = document.getElementById('cookie-preferences-modal');
      const backdrop = document.getElementById('cookie-preferences-backdrop') || document.getElementById('reader-profile-backdrop');
      if (modal) {
        const consent = this.getConsent();
        const cats = consent?.categories || { essential: true, preferences: true, analytics: false };
        const prefOpt = document.getElementById('pref-category-preferences');
        const analOpt = document.getElementById('pref-category-analytics');
        if (prefOpt) prefOpt.checked = cats.preferences !== false;
        if (analOpt) analOpt.checked = !!cats.analytics;
        modal.classList.add('is-open');
        if (backdrop) backdrop.classList.add('is-open');
        modal.setAttribute('aria-hidden', 'false');
      }
    }

    closeCookiePreferences() {
      const modal = document.getElementById('cookie-preferences-modal');
      const backdrop = document.getElementById('cookie-preferences-backdrop') || document.getElementById('reader-profile-backdrop');
      if (modal) {
        modal.classList.remove('is-open');
        modal.setAttribute('aria-hidden', 'true');
      }
      const profileModal = document.getElementById('reader-profile-modal');
      if (backdrop && (!profileModal || !profileModal.classList.contains('is-open'))) {
        backdrop.classList.remove('is-open');
      }
    }

    saveCustomCookiePreferences() {
      const prefOpt = document.getElementById('pref-category-preferences');
      const analOpt = document.getElementById('pref-category-analytics');
      const custom = {
        essential: true,
        preferences: prefOpt ? prefOpt.checked : true,
        analytics: analOpt ? analOpt.checked : false,
        marketing: false
      };
      this.saveConsent('custom', custom);
    }

    /* -------------------------------------------------------------------------
     * 6. GLOBAL EVENT BINDINGS & HELPERS
     * ---------------------------------------------------------------------- */

    /* -------------------------------------------------------------------------
     * 4.1 DEDICATED READER PROFILE PAGE CONTROLLER (/profile.html)
     * ---------------------------------------------------------------------- */
    async initProfilePage() {
      const authView = document.getElementById('profile-authenticated-view');
      const guestView = document.getElementById('profile-guest-view');
      if (!authView || !guestView) return;

      const ident = await this.getValidatedIdentity();

      if (ident.isAuthenticated) {
        if (authView.style) authView.style.display = 'block';
        if (guestView.style) guestView.style.display = 'none';

        // 1. Authoritative Database Profile Retrieval (public.profiles)
        let dbProfile = null;
        if (this.supabase && this.session?.user?.id) {
          try {
            const { data, error } = await this.supabase
              .from('profiles')
              .select('id, display_name, bio, avatar_url, updated_at')
              .eq('id', this.session.user.id)
              .maybeSingle();
            if (!error && data) {
              dbProfile = data;
              this.profile = data;
              this._lastKnownCloudUpdatedAt = data.updated_at;
              if (typeof data.bio === 'string') {
                try { localStorage.setItem('gct_reader_bio', data.bio); } catch {}
              }
            } else if (error) {
              console.warn('[GCT Auth] Database profile query error:', { code: error.code, message: error.message });
            }
          } catch (e) {
            console.warn('[GCT Auth] Database profile query exception:', { message: e?.message });
          }
        }

        // 2. Check for unsynced local draft with strict validation and user isolation
        const localDraft = this.getValidatedProfileDraft(this.session?.user?.id);

        // 3. Resolve authoritative cloud values vs unsynced draft
        const cloudDisplayName = dbProfile?.display_name || ident.displayName;
        const cloudBio = dbProfile?.bio ?? '';
        const effectiveAvatarUrl = ident.avatarUrl;

        let initialName = cloudDisplayName;
        let initialBio = cloudBio;
        let hasUnsyncedDraft = false;

        if (localDraft) {
          const cloudTime = dbProfile?.updated_at ? new Date(dbProfile.updated_at).getTime() : 0;
          if (localDraft.timestamp > cloudTime) {
            // Group B.10: Draft is newer than cloud profile -> restore into form inputs
            if (localDraft.name) initialName = localDraft.name;
            if (typeof localDraft.bio === 'string') initialBio = localDraft.bio;
            hasUnsyncedDraft = true;
          } else {
            // Group B.9: Draft is older or equal -> discard stale draft, load cloud profile
            try { localStorage.removeItem(STORAGE_KEYS.PROFILE_DRAFT); } catch {}
          }
        } else if (!dbProfile && localStorage.getItem('gct_reader_bio')) {
          initialBio = localStorage.getItem('gct_reader_bio') || '';
        }

        // Profile Overview (authoritative cloud values)
        const nameEl = document.getElementById('overview-display-name');
        const emailEl = document.getElementById('overview-email');
        const avatarEl = document.getElementById('profile-avatar-large');

        if (nameEl) {
          nameEl.innerHTML = `
            <span>${this.escape(cloudDisplayName)}</span>
            <span class="badge bg-success font-jetbrains" id="overview-status-badge" style="font-size: 11px; padding: 4px 8px;">
              ● Google Verified
            </span>
          `;
        }
        if (emailEl) emailEl.textContent = ident.email;
        if (avatarEl) {
          const initials = (cloudDisplayName || 'Reader').split(' ').map(n => n[0]).slice(0, 2).join('').toUpperCase();
          if (effectiveAvatarUrl && this.isTrustedGoogleAvatarUrl(effectiveAvatarUrl)) {
            avatarEl.innerHTML = `<img src="${this.escape(effectiveAvatarUrl)}" alt="${this.escape(cloudDisplayName)}" onerror="this.onerror=null; this.parentElement.innerHTML='<span class=\\'font-jetbrains\\' style=\\'font-size: 24px; font-weight: 700;\\'>${this.escape(initials)}</span>';" />`;
          } else {
            avatarEl.innerHTML = `<span class="font-jetbrains" style="font-size: 24px; font-weight: 700;">${this.escape(initials)}</span>`;
          }
        }

        // Section 01 General Settings
        const formName = document.getElementById('profile-form-name');
        const formEmail = document.getElementById('profile-form-email');
        const formBio = document.getElementById('profile-form-bio');

        if (formName) formName.value = initialName;
        if (formEmail) formEmail.value = ident.email;
        if (formBio) formBio.value = initialBio;

        const saveGeneralBtn = document.getElementById('profile-btn-save-general');
        if (saveGeneralBtn) {
          if (hasUnsyncedDraft) {
            saveGeneralBtn.textContent = 'Sync Changes to Cloud';
            this.showToast('Restored unsynced local draft. Click "Sync Changes to Cloud" to save.', 'info');
          } else {
            saveGeneralBtn.textContent = 'Save Profile Changes';
          }

          saveGeneralBtn.onclick = async () => {
            if (this._isSavingProfile) {
              console.warn('[GCT Auth] Save already in progress, ignoring duplicate submission.');
              return;
            }
            this._isSavingProfile = true;

            try {
              const newName = formName?.value.trim();
              const newBio = formBio?.value.trim() || '';
              if (!newName) {
                this.showToast('Display name cannot be empty.', 'error');
                return;
              }
              if (newName.length > 100) {
                this.showToast('Display name cannot exceed 100 characters.', 'error');
                return;
              }
              if (newBio.length > 250) {
                this.showToast('Biography cannot exceed 250 characters.', 'error');
                return;
              }

              // Session check
              if (!this.session || !this.session.user?.id) {
                this.showToast('Authentication required. Please sign in to save your profile.', 'error');
                return;
              }

              const nowSec = Math.floor(Date.now() / 1000);
              if (this.session.expires_at && (this.session.expires_at <= nowSec)) {
                this.saveProfileDraftSafely(this.session.user.id, newName, newBio, 'session_expired');
                this.showToast('Your session has expired. Please sign in again to save your profile.', 'error');
                saveGeneralBtn.textContent = 'Retry Save Changes';
                return;
              }

              // Pre-retry / pre-save cloud conflict check against remote updates
              const existingDraft = this.getValidatedProfileDraft(this.session.user.id);
              if (existingDraft && this.supabase) {
                try {
                  const { data: latestCloud, error: fetchErr } = await this.supabase
                    .from('profiles')
                    .select('updated_at')
                    .eq('id', this.session.user.id)
                    .maybeSingle();

                  if (!fetchErr && latestCloud?.updated_at) {
                    const cloudTime = new Date(latestCloud.updated_at).getTime();
                    if (cloudTime > existingDraft.timestamp) {
                      console.warn('[GCT Auth] Cloud profile is newer than local draft. Aborting overwrite.');
                      this.showToast('Cloud profile was updated on another device. Please refresh before saving.', 'error');
                      saveGeneralBtn.textContent = 'Refresh to View Latest';
                      saveGeneralBtn.onclick = () => window.location.reload();
                      return;
                    }
                  }
                } catch (fetchEx) {
                  console.warn('[GCT Auth] Pre-save cloud re-fetch notice:', fetchEx?.message);
                }
              }

              saveGeneralBtn.disabled = true;
              saveGeneralBtn.textContent = 'Saving to Database...';

              let dbPersisted = false;
              let dbErrorMessage = null;
              let conflictDetected = false;

              try {
                if (this.supabase) {
                  const nowIso = new Date().toISOString();

                  // Pre-check if _lastKnownCloudUpdatedAt is not yet cached
                  if (!this._lastKnownCloudUpdatedAt) {
                    const { data: cloudRow } = await this.supabase
                      .from('profiles')
                      .select('id, updated_at')
                      .eq('id', this.session.user.id)
                      .maybeSingle();
                    if (cloudRow?.updated_at) {
                      this._lastKnownCloudUpdatedAt = cloudRow.updated_at;
                    }
                  }

                  let dbErr = null;

                  if (this._lastKnownCloudUpdatedAt) {
                    // ATOMIC CONDITIONAL OCC UPDATE
                    // PostgREST translates this to UPDATE public.profiles SET ... WHERE id = $1 AND updated_at = $2 RETURNING id, updated_at
                    const { data: updatedRows, error: updateErr } = await this.supabase
                      .from('profiles')
                      .update({
                        display_name: newName,
                        bio: newBio,
                        updated_at: nowIso
                      })
                      .eq('id', this.session.user.id)
                      .eq('updated_at', this._lastKnownCloudUpdatedAt)
                      .select('id, updated_at');

                    if (updateErr) {
                      dbErr = updateErr;
                    } else if (!updatedRows || updatedRows.length === 0) {
                      // Zero rows updated: Check if row exists (OCC conflict) or was deleted
                      const { data: existingRow } = await this.supabase
                        .from('profiles')
                        .select('id, updated_at')
                        .eq('id', this.session.user.id)
                        .maybeSingle();

                      if (existingRow) {
                        conflictDetected = true;
                        dbErrorMessage = 'Cloud conflict: Your profile was modified in another session. Please reload to review the latest changes.';
                      } else {
                        const { error: insertErr } = await this.supabase
                          .from('profiles')
                          .insert({
                            id: this.session.user.id,
                            display_name: newName,
                            bio: newBio,
                            updated_at: nowIso
                          });
                        if (insertErr) {
                          dbErr = insertErr;
                        } else {
                          dbPersisted = true;
                          this._lastKnownCloudUpdatedAt = nowIso;
                        }
                      }
                    } else {
                      dbPersisted = true;
                      this._lastKnownCloudUpdatedAt = updatedRows[0].updated_at || nowIso;
                    }
                  } else {
                    // No prior row in cloud: attempt insert
                    const { error: insertErr } = await this.supabase
                      .from('profiles')
                      .insert({
                        id: this.session.user.id,
                        display_name: newName,
                        bio: newBio,
                        updated_at: nowIso
                      });
                    if (insertErr) {
                      if (insertErr.code === '23505') {
                        conflictDetected = true;
                        dbErrorMessage = 'Cloud conflict: Your profile was created in another session. Please reload to review latest changes.';
                      } else {
                        dbErr = insertErr;
                      }
                    } else {
                      dbPersisted = true;
                      this._lastKnownCloudUpdatedAt = nowIso;
                    }
                  }

                  if (dbErr) {
                    console.error('[GCT Auth] Database profile write rejected:', {
                      code: dbErr.code,
                      message: dbErr.message,
                      status: dbErr.status || dbErr.statusCode
                    });

                    if (dbErr.code === '42501' || dbErr.status === 401 || dbErr.status === 403) {
                      dbErrorMessage = 'Access denied: Database security policy prevented saving your profile.';
                    } else {
                      dbErrorMessage = `Database error (${dbErr.code || 'sync_failed'}): ${dbErr.message || 'Unable to persist profile.'}`;
                    }
                  } else if (dbPersisted) {
                    this.profile = {
                      ...(this.profile || {}),
                      id: this.session.user.id,
                      display_name: newName,
                      bio: newBio,
                      updated_at: this._lastKnownCloudUpdatedAt || nowIso
                    };
                  }
                } else {
                  dbErrorMessage = 'Database client is not available.';
                }
              } catch (err) {
                console.error('[GCT Auth] Network or unexpected exception during database save:', {
                  name: err?.name,
                  message: err?.message
                });
                dbErrorMessage = 'Network error: Unable to connect to the database. Changes not saved to cloud.';
              }

              if (dbPersisted) {
                // 1. Clear unsynced draft
                try {
                  localStorage.removeItem(STORAGE_KEYS.PROFILE_DRAFT);
                } catch {}

                // 2. Update local cache ONLY after confirmed DB persistence
                try {
                  localStorage.setItem('gct_reader_bio', newBio);
                } catch {}

                // 3. Auth metadata coherence sync (non-fatal)
                const cfg = window.__GCT_CONFIG__ || {};
                if (this.session?.access_token && cfg.supabaseUrl && cfg.anonKey) {
                  try {
                    const patchRes = await fetch(`${cfg.supabaseUrl}/auth/v1/user`, {
                      method: 'PUT',
                      headers: {
                        apikey: cfg.anonKey,
                        Authorization: `Bearer ${this.session.access_token}`,
                        'Content-Type': 'application/json'
                      },
                      body: JSON.stringify({
                        data: { full_name: newName, bio: newBio }
                      })
                    });

                    if (patchRes.ok) {
                      const updatedUser = await patchRes.json();
                      if (this.session) {
                        this.session.user = updatedUser;
                        localStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(this.session));
                      }
                    }
                  } catch (metaErr) {
                    console.warn('[GCT Auth] Metadata sync notice (non-fatal):', metaErr?.message);
                  }
                }

                // 4. Update Overview display name and Nav capsule
                if (nameEl) {
                  nameEl.innerHTML = `
                    <span>${this.escape(newName)}</span>
                    <span class="badge bg-success font-jetbrains" id="overview-status-badge" style="font-size: 11px; padding: 4px 8px;">
                      ● Google Verified
                    </span>
                  `;
                }
                this.renderNavWidget();

                // 5. Explicit cloud-save success toast
                this.showToast('Profile saved directly to database.', 'success');
                saveGeneralBtn.textContent = 'Save Profile Changes';
              } else {
                // FAILED DATABASE WRITE OR OCC CONFLICT
                // 1. NEVER display success toast
                // 2. Preserve entered values in DOM and in local draft safely
                this.saveProfileDraftSafely(this.session.user.id, newName, newBio, conflictDetected ? 'cloud_conflict' : dbErrorMessage);

                // 3. Explicit error toast
                this.showToast(dbErrorMessage || 'Database synchronization failed. Changes not saved to cloud.', 'error');

                // 4. Button state
                if (conflictDetected) {
                  saveGeneralBtn.textContent = 'Reload to Resolve Conflict';
                  saveGeneralBtn.onclick = () => window.location.reload();
                } else {
                  saveGeneralBtn.textContent = 'Retry Save Changes';
                }
              }
            } finally {
              this._isSavingProfile = false;
              if (saveGeneralBtn) saveGeneralBtn.disabled = false;
            }
          };
        }

        // Section 02 Account & Identity
        const provContainer = document.getElementById('profile-connected-providers');
        if (provContainer) {
          provContainer.innerHTML = `
            <div class="auth-provider-card auth-provider-connected">
              <div class="d-flex align-items-center gap-3">
                <span class="provider-icon-wrap" aria-hidden="true">
                  <svg width="20" height="20" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/></svg>
                </span>
                <div>
                  <div class="auth-provider-title font-jetbrains">Google Federated Identity</div>
                  <div class="auth-provider-status font-jetbrains">
                    <span class="provider-status-dot"></span>
                    <span>Connected as ${this.escape(ident.email)} &bull; Verified</span>
                  </div>
                </div>
              </div>
              <button type="button" class="btn btn-secondary btn-sm font-jetbrains profile-btn-prov-signout" id="profile-btn-prov-signout">
                Sign Out
              </button>
            </div>
          `;

          document.getElementById('profile-btn-prov-signout')?.addEventListener('click', () => this.signOut());
        }

        document.getElementById('overview-btn-signout')?.addEventListener('click', () => this.signOut());

        document.getElementById('profile-btn-request-deletion')?.addEventListener('click', () => {
          if (confirm('Initiate Server-Side Deletion Request?\n\nIn accordance with DPDP Act 2023 / GDPR, this request purges your personal credentials and identity attribution across GreyCircuit systems. Local session tokens will also be revoked.')) {
            this.deleteAccount();
          }
        });

        // Section 03 My Activity
        this.renderProfileActivity(ident);

        // Section 04 Bookmarked Publications (Phase C)
        await this.renderBookmarksSection();

        // Section 05 Privacy & Data Rights
        document.getElementById('profile-btn-export-data')?.addEventListener('click', () => this.exportPersonalData());
        document.getElementById('profile-btn-manage-consent')?.addEventListener('click', () => this.openCookiePreferences());

      } else {
        // Guest mode view
        if (authView.style) authView.style.display = 'none';
        if (guestView.style) guestView.style.display = 'block';

        const guestSigninBtn = document.getElementById('btn-profile-guest-signin');
        if (guestSigninBtn) {
          guestSigninBtn.onclick = () => {
            const absProfileUrl = new URL('profile.html', window.location.href).href;
            this.signInWithGoogle(absProfileUrl);
          };
        }
      }
    }

    renderProfileActivity(ident) {
      const activityContainer = document.getElementById('profile-activity-list');
      const commentsBadge = document.getElementById('stat-comments-count');
      const likesBadge = document.getElementById('stat-likes-count');
      if (!activityContainer) return;

      const comments = JSON.parse(localStorage.getItem('gct_user_comments_history') || '[]');

      const likedArticles = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith('gct_liked_art_') && localStorage.getItem(key) === 'true') {
          likedArticles.push(key.replace('gct_liked_art_', ''));
        }
      }

      if (commentsBadge) commentsBadge.textContent = `${comments.length} Comments`;
      if (likesBadge) likesBadge.textContent = `${likedArticles.length} Likes`;

      if (comments.length === 0 && likedArticles.length === 0) {
        activityContainer.innerHTML = `
          <div class="empty-engagement-history">
            No comments, replies, or article interactions recorded yet. Engage with technical publications to build your activity history.
          </div>
        `;
        return;
      }

      let html = '';

      comments.forEach(item => {
        const isReply = !!item.isReply;
        const dateStr = item.timestamp ? new Date(item.timestamp).toLocaleDateString() : 'Recent';
        const pubUrl = item.articleSlug ? `article.html?slug=${encodeURIComponent(item.articleSlug)}` : 'index.html';
        const pubTitle = item.articleTitle || 'GCT Publication';

        html += `
          <div class="activity-item-card">
            <div class="activity-item-top">
              <div class="d-flex align-items-center gap-2">
                <span class="badge ${isReply ? 'bg-info' : 'bg-primary'} font-jetbrains" style="font-size: 10px;">
                  ${isReply ? 'Reply' : 'Comment'}
                </span>
                <span class="font-mono text-2xs text-muted">${dateStr}</span>
                <span class="badge bg-secondary font-jetbrains" style="font-size: 10px; background: rgba(52,211,153,0.1) !important; color: #34d399;">Published</span>
              </div>
              <a href="${pubUrl}" class="activity-item-pub-link">
                ${this.escape(pubTitle)} →
              </a>
            </div>
            <div class="activity-item-body">
              ${this.escape(item.content)}
            </div>
          </div>
        `;
      });

      likedArticles.forEach(artId => {
        html += `
          <div class="activity-item-card">
            <div class="activity-item-top">
              <div class="d-flex align-items-center gap-2">
                <span class="badge bg-secondary font-jetbrains" style="font-size: 10px; background: rgba(124,58,237,0.2) !important; color: #c4b5fd;">
                  Article Liked
                </span>
                <span class="font-mono text-2xs text-muted">ID: ${artId.substring(0, 8)}...</span>
              </div>
              <a href="index.html" class="activity-item-pub-link">View in Publications Catalog →</a>
            </div>
          </div>
        `;
      });

      activityContainer.innerHTML = html;
    }

    bindGlobalEvents() {
      window.addEventListener('resize', () => this.alignProfileWidget());
      window.addEventListener('scroll', () => this.alignProfileWidget(), { passive: true });

      // Synchronize site-nav animation state to reader-profile-widget via MutationObserver
      const nav = document.getElementById('site-nav');
      if (nav && typeof MutationObserver !== 'undefined') {
        const navObserver = new MutationObserver((mutations) => {
          for (const m of mutations) {
            if (m.type === 'attributes' && m.attributeName === 'class') {
              const widget = document.getElementById('reader-profile-widget');
              if (widget) {
                widget.classList.toggle('is-scrolled', nav.classList.contains('is-scrolled'));
                widget.classList.toggle('is-hidden', nav.classList.contains('is-hidden'));
              }
            }
          }
        });
        navObserver.observe(nav, { attributes: true, attributeFilter: ['class'] });
      }

      // Automatically recalculate position if navigation island size changes (font loading, window changes)
      if (nav && typeof ResizeObserver !== 'undefined') {
        const resizeObserver = new ResizeObserver(() => this.alignProfileWidget());
        resizeObserver.observe(nav);
      }
      if (document.fonts && document.fonts.ready) {
        document.fonts.ready.then(() => this.alignProfileWidget());
      }
      window.addEventListener('load', () => this.alignProfileWidget());

      // State-dependent profile icon action (Section 2.1)
      const handleProfileNav = async (e) => {
        if (e) e.preventDefault();
        if (this.isNavigating) return;
        this.isNavigating = true;

        const btn = document.getElementById('btn-reader-profile');
        if (btn) btn.classList.add('is-loading');

        try {
          const ident = await this.getValidatedIdentity();
          if (ident.isAuthenticated) {
            const currentPath = (typeof window !== 'undefined' && window.location?.pathname) || '';
            const isProfilePage = currentPath.endsWith('profile.html');
            if (!isProfilePage) {
              window.location.href = 'profile.html';
            }
          } else {
            this.openProfileModal();
          }
        } catch (err) {
          console.warn('[GCT Auth] Error during profile navigation check:', err);
          this.openProfileModal();
        } finally {
          this.isNavigating = false;
          if (btn) btn.classList.remove('is-loading');
        }
      };

      const btn = document.getElementById('btn-reader-profile');
      if (btn) {
        btn.addEventListener('click', handleProfileNav);
      }

      const mobBtn = document.getElementById('btn-mobile-reader-profile');
      if (mobBtn) {
        mobBtn.addEventListener('click', async (e) => {
          const drawer = document.getElementById('mobile-drawer');
          const backdrop = document.getElementById('mobile-drawer-backdrop');
          if (drawer) drawer.classList.remove('is-open');
          if (backdrop) backdrop.hidden = true;
          await handleProfileNav(e);
        });
      }

      // Privacy preferences button inside modal
      document.getElementById('modal-btn-privacy-pref')?.addEventListener('click', () => this.openCookiePreferences());

      // Close modal buttons
      document.querySelectorAll('.btn-close-profile-modal').forEach(b => {
        b.addEventListener('click', () => this.closeProfileModal());
      });

      // Save profile button
      document.getElementById('modal-btn-save-profile')?.addEventListener('click', () => this.saveProfile());

      // Export data button
      document.getElementById('modal-btn-export-data')?.addEventListener('click', () => this.exportPersonalData());

      // Delete account button
      document.getElementById('modal-btn-delete-account')?.addEventListener('click', () => this.deleteAccount());

      // Consent buttons
      document.getElementById('btn-consent-accept-all')?.addEventListener('click', () => this.saveConsent('accept_all'));
      document.getElementById('btn-consent-reject-opt')?.addEventListener('click', () => this.saveConsent('reject_optional'));
      document.getElementById('btn-consent-manage')?.addEventListener('click', () => this.openCookiePreferences());
      document.getElementById('link-privacy-preferences')?.addEventListener('click', (e) => {
        e.preventDefault();
        this.openCookiePreferences();
      });

      // Cookie preferences modal buttons & backdrop
      document.querySelectorAll('.btn-close-cookie-modal').forEach(b => {
        b.addEventListener('click', () => this.closeCookiePreferences());
      });
      document.getElementById('cookie-preferences-backdrop')?.addEventListener('click', () => this.closeCookiePreferences());
      document.getElementById('btn-save-cookie-preferences')?.addEventListener('click', () => this.saveCustomCookiePreferences());
      document.getElementById('btn-pref-reject-all')?.addEventListener('click', () => {
        this.saveConsent('reject_optional');
        this.closeCookiePreferences();
      });
    }

    /* -------------------------------------------------------------------------
     * 7. ARTICLE BOOKMARKS CONTROLLER (Phase C)
     * ---------------------------------------------------------------------- */
    getBookmarksFromCache(userId) {
      if (!userId) return [];
      try {
        const raw = localStorage.getItem(`${STORAGE_KEYS.BOOKMARKS_CACHE}_${userId}`);
        if (!raw) return [];
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
      } catch (e) {
        return [];
      }
    }

    saveBookmarksToCache(userId, bookmarks) {
      if (!userId) return;
      try {
        localStorage.setItem(`${STORAGE_KEYS.BOOKMARKS_CACHE}_${userId}`, JSON.stringify(bookmarks || []));
      } catch (e) {
        console.warn('[GCT Bookmarks] Local storage bookmark cache error:', e);
      }
    }

    async isArticleBookmarked(articleId) {
      if (!articleId) return false;
      const ident = this.getIdentity();
      if (!ident.isAuthenticated || !this.session?.user?.id) return false;
      const userId = this.session.user.id;

      // 1. Check local cache first
      const cache = this.getBookmarksFromCache(userId);
      const isCached = cache.some(b => b.article_id === articleId);

      // 2. Query Supabase if connected
      if (this.supabase) {
        try {
          const { data, error } = await this.supabase
            .from('article_bookmarks')
            .select('id, created_at')
            .eq('user_id', userId)
            .eq('article_id', articleId)
            .maybeSingle();

          if (!error) {
            const isDbBookmarked = Boolean(data);
            if (isDbBookmarked && !isCached) {
              cache.unshift({
                id: data.id,
                user_id: userId,
                article_id: articleId,
                created_at: data.created_at
              });
              this.saveBookmarksToCache(userId, cache);
            } else if (!isDbBookmarked && isCached) {
              const filtered = cache.filter(b => b.article_id !== articleId);
              this.saveBookmarksToCache(userId, filtered);
              return false;
            }
            return isDbBookmarked;
          }
        } catch {}
      }

      return isCached;
    }

    async toggleBookmark(articleId, articleMeta = {}) {
      if (!articleId) return { success: false, reason: 'missing_id' };

      const ident = this.getIdentity();
      if (!ident.isAuthenticated || !this.session?.user?.id) {
        this.showToast('Please sign in with Google to bookmark publications.', 'info');
        this.openProfileModal();
        return { success: false, reason: 'unauthenticated' };
      }

      const userId = this.session.user.id;
      let cache = this.getBookmarksFromCache(userId);
      const existingIndex = cache.findIndex(b => b.article_id === articleId);
      const isCurrentlyBookmarked = existingIndex !== -1;

      if (isCurrentlyBookmarked) {
        // REMOVE BOOKMARK
        cache.splice(existingIndex, 1);
        this.saveBookmarksToCache(userId, cache);

        if (this.supabase) {
          try {
            await this.supabase
              .from('article_bookmarks')
              .delete()
              .eq('user_id', userId)
              .eq('article_id', articleId);
          } catch (e) {
            console.warn('[GCT Bookmarks] DB delete notice:', e?.message);
          }
        }

        this.showToast('Publication removed from your bookmarks.', 'info');
        window.dispatchEvent(new CustomEvent('gct:bookmark-updated', {
          detail: { articleId, bookmarked: false }
        }));
        return { success: true, bookmarked: false };
      } else {
        // ADD BOOKMARK (Prevent duplicates in client and DB)
        const bookmarkRecord = {
          id: typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : 'bm_' + Date.now().toString(36),
          user_id: userId,
          article_id: articleId,
          slug: articleMeta.slug || '',
          title: articleMeta.title || 'Technical Publication',
          reading_time: articleMeta.reading_time || null,
          created_at: new Date().toISOString()
        };

        if (this.supabase) {
          try {
            const { data, error } = await this.supabase
              .from('article_bookmarks')
              .insert({
                user_id: userId,
                article_id: articleId
              })
              .select('id, created_at');

            if (!error && data && data.length > 0) {
              bookmarkRecord.id = data[0].id;
              bookmarkRecord.created_at = data[0].created_at;
            }
          } catch (e) {
            console.warn('[GCT Bookmarks] DB insert notice:', e?.message);
          }
        }

        cache.unshift(bookmarkRecord);
        this.saveBookmarksToCache(userId, cache);

        this.showToast('Publication saved to your bookmarks.', 'success');
        window.dispatchEvent(new CustomEvent('gct:bookmark-updated', {
          detail: { articleId, bookmarked: true }
        }));
        return { success: true, bookmarked: true };
      }
    }

    async syncLocalBookmarksToDatabase(userId) {
      if (!userId || !this.supabase) return this.getBookmarksFromCache(userId);
      const cached = this.getBookmarksFromCache(userId);

      try {
        // 1. Fetch existing bookmarks for this user from DB
        const { data: dbData, error: dbErr } = await this.supabase
          .from('article_bookmarks')
          .select('id, article_id, created_at')
          .eq('user_id', userId);

        if (dbErr) {
          // If table doesn't exist yet (pre-migration) or network error, return cached bookmarks safely
          return cached;
        }

        const existingDbArticleIds = new Set((dbData || []).map(r => r.article_id));

        // 2. Find local bookmarks that haven't been synchronized to the database
        const unsynced = cached.filter(b => b.article_id && !existingDbArticleIds.has(b.article_id));

        // 3. Upsert / Insert unsynced bookmarks to DB
        for (const item of unsynced) {
          try {
            const { error: insErr } = await this.supabase
              .from('article_bookmarks')
              .insert({
                user_id: userId,
                article_id: item.article_id
              });
            if (insErr && insErr.code !== '23505' && !insErr.message?.includes('duplicate')) {
              console.warn('[GCT Bookmarks] Sync insert warning:', item.article_id, insErr.message);
            }
          } catch (e) {
            console.warn('[GCT Bookmarks] Sync insert exception:', e?.message);
          }
        }

        // 4. Fetch the authoritative consolidated list joined with articles
        const { data: joinedData, error: joinErr } = await this.supabase
          .from('article_bookmarks')
          .select(`
            id,
            article_id,
            created_at,
            articles (
              id,
              title,
              slug,
              published_at,
              reading_time_minutes
            )
          `)
          .eq('user_id', userId)
          .order('created_at', { ascending: false });

        if (!joinErr && Array.isArray(joinedData)) {
          const syncedList = joinedData
            .filter(item => item.articles && item.articles.slug)
            .map(item => ({
              id: item.id,
              user_id: userId,
              article_id: item.article_id,
              slug: item.articles.slug,
              title: item.articles.title || 'Publication',
              reading_time: item.articles.reading_time_minutes || null,
              created_at: item.created_at,
              is_synced: true
            }));

          // Preserve any local items that could not be joined to prevent silent data loss
          const syncedArticleIds = new Set(syncedList.map(item => item.article_id));
          const remainingLocal = cached.filter(item => !syncedArticleIds.has(item.article_id));
          const consolidated = [...syncedList, ...remainingLocal];

          this.saveBookmarksToCache(userId, consolidated);
          return consolidated;
        }
      } catch (err) {
        console.warn('[GCT Bookmarks] Sync cycle notice:', err?.message);
      }

      return cached;
    }

    async getBookmarkedArticles() {
      const ident = this.getIdentity();
      if (!ident.isAuthenticated || !this.session?.user?.id) return [];
      const userId = this.session.user.id;

      if (this.supabase) {
        return await this.syncLocalBookmarksToDatabase(userId);
      }

      return this.getBookmarksFromCache(userId);
    }

    async renderBookmarksSection() {
      const container = document.getElementById('profile-bookmarks-list');
      const badge = document.getElementById('stat-bookmarks-count');
      if (!container) return;

      container.innerHTML = `
        <div class="empty-bookmarks font-jetbrains">
          Loading bookmarked publications...
        </div>
      `;

      try {
        const bookmarks = await this.getBookmarkedArticles();
        if (badge) badge.textContent = `${bookmarks.length} Saved`;

        if (bookmarks.length === 0) {
          container.innerHTML = `
            <div class="empty-bookmarks font-jetbrains">
              No bookmarked publications yet. Save articles while reading to build your personal technical reference library.
            </div>
          `;
          return;
        }

        container.innerHTML = `
          <div class="bookmarks-list">
            ${bookmarks.map(b => `
              <div class="bookmark-item-card" data-article-id="${this.escape(b.article_id)}">
                <div class="bookmark-item-info">
                  <a href="article.html?slug=${encodeURIComponent(b.slug)}" class="bookmark-item-title font-jetbrains">
                    ${this.escape(b.title)}
                  </a>
                  <div class="bookmark-item-meta">
                    <span>Saved ${new Date(b.created_at).toLocaleDateString()}</span>
                    ${b.reading_time ? `<span>&bull; ${b.reading_time} min read</span>` : ''}
                  </div>
                </div>
                <div class="bookmark-item-actions">
                  <a href="article.html?slug=${encodeURIComponent(b.slug)}" class="btn btn-secondary btn-sm font-jetbrains" style="font-size: 11px; padding: 4px 10px;">Read →</a>
                  <button type="button" class="btn-remove-bookmark font-jetbrains" data-article-id="${this.escape(b.article_id)}" title="Remove bookmark">
                    Remove
                  </button>
                </div>
              </div>
            `).join('')}
          </div>
        `;

        container.querySelectorAll('.btn-remove-bookmark').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            const artId = btn.getAttribute('data-article-id');
            if (artId) {
              btn.disabled = true;
              btn.textContent = 'Removing...';
              await this.toggleBookmark(artId);
              await this.renderBookmarksSection();
            }
          });
        });
      } catch (err) {
        console.error('[GCT Bookmarks] Render error:', err);
        container.innerHTML = `
          <div class="empty-bookmarks font-jetbrains" style="color: #fca5a5;">
            Unable to load bookmarked publications at this time.
          </div>
        `;
      }
    }

    /**
     * Rigorous validation and normalization of local profile drafts.
     * Enforces strict user isolation, structural integrity, and malformed draft eviction.
     */
    getValidatedProfileDraft(currentUserId) {
      if (!currentUserId) return null;
      try {
        const raw = localStorage.getItem(STORAGE_KEYS.PROFILE_DRAFT);
        if (!raw) return null;

        let parsed = null;
        try {
          parsed = JSON.parse(raw);
        } catch (jsonErr) {
          console.warn('[GCT Auth] Corrupted draft JSON detected; discarding malformed entry.');
          try { localStorage.removeItem(STORAGE_KEYS.PROFILE_DRAFT); } catch {}
          return null;
        }

        if (!parsed || typeof parsed !== 'object') {
          try { localStorage.removeItem(STORAGE_KEYS.PROFILE_DRAFT); } catch {}
          return null;
        }

        // Strict User Isolation: Must match current authenticated user UUID
        if (!parsed.userId || parsed.userId !== currentUserId) {
          // Foreign or unassigned draft detected; purge to protect user privacy and avoid cross-account leaks
          try { localStorage.removeItem(STORAGE_KEYS.PROFILE_DRAFT); } catch {}
          return null;
        }

        // Must carry unsynced flag
        if (parsed.unsynced !== true) {
          try { localStorage.removeItem(STORAGE_KEYS.PROFILE_DRAFT); } catch {}
          return null;
        }

        // Timestamp must be a valid, finite positive integer
        const ts = Number(parsed.timestamp);
        if (!Number.isFinite(ts) || ts <= 0) {
          console.warn('[GCT Auth] Draft contains invalid timestamp; discarding.');
          try { localStorage.removeItem(STORAGE_KEYS.PROFILE_DRAFT); } catch {}
          return null;
        }

        // Normalization
        const normName = typeof parsed.name === 'string' ? parsed.name.trim() : '';
        const normBio = typeof parsed.bio === 'string' ? parsed.bio.trim() : '';

        // Empty display name and empty bio: discard malformed empty draft
        if (!normName && !normBio) {
          console.warn('[GCT Auth] Draft contains empty name and empty bio; discarding.');
          try { localStorage.removeItem(STORAGE_KEYS.PROFILE_DRAFT); } catch {}
          return null;
        }

        return {
          userId: parsed.userId,
          name: normName,
          bio: normBio,
          timestamp: ts,
          unsynced: true,
          error: parsed.error || null
        };
      } catch (err) {
        console.warn('[GCT Auth] Profile draft evaluation notice:', err);
        return null;
      }
    }

    /**
     * Safe storage of local profile draft with quota protection.
     */
    saveProfileDraftSafely(userId, name, bio, errorMsg) {
      if (!userId) return;
      try {
        const payload = JSON.stringify({
          userId: userId,
          name: typeof name === 'string' ? name.trim() : '',
          bio: typeof bio === 'string' ? bio.trim() : '',
          timestamp: Date.now(),
          unsynced: true,
          error: errorMsg || null
        });
        localStorage.setItem(STORAGE_KEYS.PROFILE_DRAFT, payload);
      } catch (quotaErr) {
        console.warn('[GCT Auth] Local storage write failed (quota exceeded or storage blocked):', quotaErr?.message);
      }
    }

    escape(str) {
      return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    showToast(message, type = 'info') {
      let toast = document.getElementById('gct-reader-toast');
      if (!toast) {
        toast = document.createElement('div');
        toast.id = 'gct-reader-toast';
        toast.className = 'gct-toast-container font-jetbrains';
        document.body.appendChild(toast);
      }
      toast.textContent = message;
      toast.className = `gct-toast-container font-jetbrains toast-${type} is-active`;
      setTimeout(() => {
        toast.classList.remove('is-active');
      }, 4000);
    }
  }

  // Export Singleton to Window
  window.ReaderClient = new ReaderClient();
  window.readerClient = window.ReaderClient;
  window.GCTReader = window.ReaderClient;
})();
