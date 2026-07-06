        (function () {
            'use strict';

            var CONFIG = Object.freeze({
                CLIENT_ID: '694517401702-4oidkp8p8h9fcpkst0d76o7tn10r1vqq.apps.googleusercontent.com',
                ALLOWED_EMAILS: Object.freeze([
                    'neerajkumar.billfree@gmail.com',
                    'suraj.billfree2@gmail.com',
                    'veer.billfree@gmail.com',
                    'gaurav.pal@billfree.in'
                ]),
                WEBAPP_URL: 'https://script.google.com/macros/s/AKfycbwJcHg5ToptJlv2OV4r3eCdOnmtzh0HC-ahvBmriI5OsnNo1eB5_PxuZGrli83Fz0s6Mw/exec',
                TRUSTED_GAS_ORIGINS: Object.freeze([
                    'https://script.google.com',
                    'https://script.googleusercontent.com',
                    'https://script.google.com/macros/s/AKfycbwJcHg5ToptJlv2OV4r3eCdOnmtzh0HC-ahvBmriI5OsnNo1eB5_PxuZGrli83Fz0s6Mw/exec'
                ]),
                SESSION_KEY: 'billfree_auth_session_v2',
                LEGACY_SESSION_KEY: 'billfree_auth_session',
                SESSION_MAX_AGE_SECONDS: 3600,
                TOKEN_SKEW_SECONDS: 60,
                NETWORK_TIMEOUT_MS: 10000,
                DEBUG: false
            });

            var STATE = {
                googleSDKLoaded: false,
                tokenClient: null
            };

            var TRUSTED_ORIGINS = buildTrustedOrigins_();
            var ALLOWED_EMAIL_SET = new Set(
                CONFIG.ALLOWED_EMAILS.map(normalizeEmail_).filter(Boolean)
            );

            function normalizeEmail_(email) {
                return String(email || '').trim().toLowerCase();
            }

            // Gated logging — no identity/PII reaches the browser console in production.
            function dbg_() {
                if (!CONFIG.DEBUG) return;
                try { console.log.apply(console, arguments); } catch (_) { }
            }

            // Local initials avatar (SVG data URI) — avoids an external request to a
            // third party (privacy) and works offline.
            function initialsAvatar_(name) {
                var parts = String(name || 'User').trim().split(/\s+/).slice(0, 2);
                var initials = parts.map(function (p) { return p.charAt(0).toUpperCase(); }).join('') || 'U';
                var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">'
                    + '<rect width="64" height="64" fill="#667eea"/>'
                    + '<text x="50%" y="50%" dy=".35em" text-anchor="middle" '
                    + 'font-family="Inter,Arial,sans-serif" font-size="26" fill="#ffffff">' + initials + '</text></svg>';
                return 'data:image/svg+xml;charset=UTF-8,' + encodeURIComponent(svg);
            }

            function isAllowedEmail_(email) {
                return ALLOWED_EMAIL_SET.has(normalizeEmail_(email));
            }

            function nowSec_() {
                return Math.floor(Date.now() / 1000);
            }

            function safeText_(value, maxLen) {
                var text = String(value == null ? '' : value)
                    .replace(/[\u0000-\u001F\u007F]/g, '')
                    .trim();
                if (maxLen && text.length > maxLen) {
                    return text.slice(0, maxLen);
                }
                return text;
            }

            function safeImageUrl_(url) {
                try {
                    var parsed = new URL(String(url || ''));
                    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
                        return parsed.href;
                    }
                } catch (_) { }
                return '';
            }

            function showLoginView() {
                document.getElementById('login-view').style.display = 'flex';
                document.getElementById('dashboard-view').style.display = 'none';
                document.body.classList.remove('dashboard-mode');

                var frame = document.getElementById('dashboard-frame');
                if (frame && frame.src !== 'about:blank') {
                    frame.src = 'about:blank';
                }
            }

            function showDashboardView(userData) {
                document.getElementById('login-view').style.display = 'none';
                document.getElementById('dashboard-view').style.display = 'flex';
                document.body.classList.add('dashboard-mode');

                document.getElementById('user-display-name').textContent = safeText_(userData.name || userData.email, 120);
                document.getElementById('user-avatar').src = safeImageUrl_(userData.picture) ||
                    initialsAvatar_(userData.name || userData.email || 'User');

                var frame = document.getElementById('dashboard-frame');

                // Add a listener to send the token once the iframe is ready
                var messageSent = false;
                var sendIdentity = function () {
                    if (messageSent) return;
                    try {
                        var authMessage = {
                            type: 'BT_AUTH_SYNC',
                            payload: {
                                email: userData.email,
                                name: userData.name,
                                picture: userData.picture,
                                token: userData.token,
                                provider: userData.provider
                            }
                        };

                        TRUSTED_ORIGINS.forEach(function (origin) {
                            try {
                                frame.contentWindow.postMessage(authMessage, origin);
                                messageSent = true;
                            } catch (_) { }
                        });
                        dbg_('Auth sync message sent to iframe');
                    } catch (err) {
                        dbg_('Failed to send auth sync message:', err);
                    }
                };

                // Listen for a 'ready' signal from the GAS app
                if (window.__dashboardReadyHandler) {
                    window.removeEventListener('message', window.__dashboardReadyHandler);
                }

                window.__dashboardReadyHandler = function (event) {
                    if (!TRUSTED_ORIGINS.has(String(event.origin || ''))) return;
                    if (event.source !== frame.contentWindow) return;
                    if (event.data && event.data.type === 'BT_APP_READY') {
                        dbg_('Received BT_APP_READY from iframe');
                        sendIdentity();
                    }
                };

                window.addEventListener('message', window.__dashboardReadyHandler, { once: false });

                // Also send on load as a fallback
                frame.onload = function () {
                    setTimeout(sendIdentity, 1000); // Small delay to ensure listener is active
                };

                // 🌉 URL PARAMETER BRIDGE (CRITICAL FIX)
                // Pass identity via URL params — postMessage is blocked by COOP.
                // doGet reads e.parameter.eml/nm → injects as injectedUserEmail/injectedUserName
                // → SERVER_FALLBACK sets APP_USER → form autofills dynamically.
                var separator = CONFIG.WEBAPP_URL.indexOf('?') === -1 ? '?' : '&';
                var params = 'authuser=0'
                    + '&eml=' + encodeURIComponent(normalizeEmail_(userData.email))
                    + '&nm=' + encodeURIComponent(safeText_(userData.name || '', 80));

                frame.src = CONFIG.WEBAPP_URL + separator + params;
            }

            function clearStatus() {
                var statusEl = document.getElementById('status-message');
                statusEl.className = 'status-message';
                while (statusEl.firstChild) {
                    statusEl.removeChild(statusEl.firstChild);
                }
            }

            function showStatus(type, message) {
                var statusEl = document.getElementById('status-message');
                var resolvedType = String(type || 'loading').toLowerCase();
                statusEl.className = 'status-message show ' + resolvedType;

                while (statusEl.firstChild) {
                    statusEl.removeChild(statusEl.firstChild);
                }

                if (resolvedType === 'loading') {
                    var spinner = document.createElement('span');
                    spinner.className = 'spinner';
                    spinner.setAttribute('aria-hidden', 'true');
                    statusEl.appendChild(spinner);
                } else if (resolvedType === 'success' || resolvedType === 'error') {
                    var icon = document.createElement('i');
                    icon.className = resolvedType === 'success'
                        ? 'fas fa-check-circle'
                        : 'fas fa-exclamation-triangle';
                    icon.setAttribute('aria-hidden', 'true');
                    statusEl.appendChild(icon);
                    statusEl.appendChild(document.createTextNode(' '));
                }

                statusEl.appendChild(document.createTextNode(safeText_(message, 240)));
            }

            function setSignInBusy_(busy) {
                var btn = document.getElementById('custom-google-btn');
                if (btn) btn.disabled = !!busy;
            }

            function buildTrustedOrigins_() {
                var origins = new Set(CONFIG.TRUSTED_GAS_ORIGINS);
                try {
                    var url = new URL(CONFIG.WEBAPP_URL);
                    origins.add(url.origin);
                } catch (_) { }
                return origins;
            }

            function readStoredSession_() {
                var raw = null;
                try {
                    raw = sessionStorage.getItem(CONFIG.SESSION_KEY);
                } catch (_) { }

                if (!raw) {
                    try {
                        raw = localStorage.getItem(CONFIG.SESSION_KEY);
                    } catch (_) { }
                }
                if (!raw) {
                    try {
                        raw = localStorage.getItem(CONFIG.LEGACY_SESSION_KEY);
                    } catch (_) { }
                }

                if (!raw) return null;
                try {
                    return JSON.parse(raw);
                } catch (_) {
                    return null;
                }
            }

            function clearStoredSession_() {
                try {
                    sessionStorage.removeItem(CONFIG.SESSION_KEY);
                } catch (_) { }
                try {
                    sessionStorage.removeItem(CONFIG.LEGACY_SESSION_KEY);
                } catch (_) { }
                try {
                    localStorage.removeItem(CONFIG.SESSION_KEY);
                } catch (_) { }
                try {
                    localStorage.removeItem(CONFIG.LEGACY_SESSION_KEY);
                } catch (_) { }
            }

            function writeStoredSession_(session) {
                try {
                    sessionStorage.setItem(CONFIG.SESSION_KEY, JSON.stringify(session));
                } catch (_) { }
                try {
                    localStorage.removeItem(CONFIG.SESSION_KEY);
                } catch (_) { }
                try {
                    localStorage.removeItem(CONFIG.LEGACY_SESSION_KEY);
                } catch (_) { }
            }

            function isSessionShapeValid_(session) {
                return !!(
                    session &&
                    typeof session === 'object' &&
                    typeof session.email === 'string' &&
                    typeof session.provider === 'string' &&
                    typeof session.token === 'string' &&
                    Number.isFinite(Number(session.exp))
                );
            }

            function isSessionFresh_(session) {
                return Number(session.exp) > (nowSec_() + CONFIG.TOKEN_SKEW_SECONDS);
            }

            function buildSession_(identity) {
                return {
                    v: 2,
                    email: normalizeEmail_(identity.email),
                    name: safeText_(identity.name || identity.email, 120),
                    picture: safeImageUrl_(identity.picture),
                    exp: Number(identity.exp || (nowSec_() + CONFIG.SESSION_MAX_AGE_SECONDS)),
                    provider: String(identity.provider || ''),
                    token: String(identity.token || ''),
                    issuedAt: nowSec_()
                };
            }

            function decodeJwtPayload(token) {
                if (!token || typeof token !== 'string') {
                    throw new Error('Missing ID token.');
                }
                var parts = token.split('.');
                if (parts.length < 2) {
                    throw new Error('Invalid ID token format.');
                }
                var base64Url = parts[1];
                var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                while (base64.length % 4) {
                    base64 += '=';
                }
                var jsonPayload = decodeURIComponent(
                    atob(base64)
                        .split('')
                        .map(function (c) {
                            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                        })
                        .join('')
                );
                return JSON.parse(jsonPayload);
            }

            function waitForGoogleSDK_(maxWaitMs) {
                return new Promise(function (resolve) {
                    var started = Date.now();
                    (function poll() {
                        if (
                            typeof google !== 'undefined' &&
                            google.accounts &&
                            google.accounts.id &&
                            google.accounts.oauth2
                        ) {
                            resolve(true);
                            return;
                        }

                        if ((Date.now() - started) >= maxWaitMs) {
                            resolve(false);
                            return;
                        }
                        setTimeout(poll, 100);
                    })();
                });
            }

            async function fetchJsonWithTimeout_(url, options) {
                var controller = new AbortController();
                var timeout = setTimeout(function () {
                    controller.abort();
                }, CONFIG.NETWORK_TIMEOUT_MS);

                try {
                    var requestOptions = Object.assign({}, options || {}, {
                        signal: controller.signal,
                        cache: 'no-store'
                    });
                    var response = await fetch(url, requestOptions);
                    var payload = {};
                    try {
                        payload = await response.json();
                    } catch (_) {
                        payload = {};
                    }

                    if (!response.ok) {
                        var reason = safeText_(payload.error_description || payload.error || response.statusText, 180);
                        throw new Error(reason || 'Request failed.');
                    }
                    return payload;
                } finally {
                    clearTimeout(timeout);
                }
            }

            async function verifyIdToken_(idToken, expectedEmail) {
                var tokenInfo = await fetchJsonWithTimeout_(
                    'https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken)
                );

                var aud = String(tokenInfo.aud || '');
                if (aud !== CONFIG.CLIENT_ID) {
                    throw new Error('Invalid Google audience.');
                }

                var verifiedEmail = normalizeEmail_(tokenInfo.email || expectedEmail);
                if (!verifiedEmail) {
                    throw new Error('Email missing in Google token.');
                }
                if (expectedEmail && verifiedEmail !== normalizeEmail_(expectedEmail)) {
                    throw new Error('Google token email mismatch.');
                }
                if (String(tokenInfo.email_verified).toLowerCase() !== 'true') {
                    throw new Error('Google account email is not verified.');
                }
                if (!isAllowedEmail_(verifiedEmail)) {
                    throw new Error('Access denied for this account.');
                }

                var exp = Number(tokenInfo.exp || 0);
                if (!Number.isFinite(exp) || exp <= (nowSec_() + CONFIG.TOKEN_SKEW_SECONDS)) {
                    throw new Error('Google token is expired.');
                }

                return {
                    email: verifiedEmail,
                    exp: exp,
                    name: safeText_(tokenInfo.name || '', 120),
                    picture: ''
                };
            }

            async function verifyAccessToken_(accessToken, expectedEmail) {
                var tokenInfo = await fetchJsonWithTimeout_(
                    'https://oauth2.googleapis.com/tokeninfo?access_token=' + encodeURIComponent(accessToken)
                );

                var aud = String(tokenInfo.aud || tokenInfo.azp || '');
                if (aud !== CONFIG.CLIENT_ID) {
                    throw new Error('Invalid OAuth client audience.');
                }

                var expiresIn = Number(tokenInfo.expires_in || 0);
                if (!Number.isFinite(expiresIn) || expiresIn <= CONFIG.TOKEN_SKEW_SECONDS) {
                    throw new Error('Access token is expired.');
                }

                var userInfo = await fetchJsonWithTimeout_('https://www.googleapis.com/oauth2/v3/userinfo', {
                    headers: { Authorization: 'Bearer ' + accessToken }
                });

                var verifiedEmail = normalizeEmail_(userInfo.email || expectedEmail);
                if (!verifiedEmail) {
                    throw new Error('Unable to fetch account email.');
                }
                if (expectedEmail && verifiedEmail !== normalizeEmail_(expectedEmail)) {
                    throw new Error('Google account mismatch.');
                }
                if (String(userInfo.email_verified).toLowerCase() === 'false') {
                    throw new Error('Google account email is not verified.');
                }
                if (!isAllowedEmail_(verifiedEmail)) {
                    throw new Error('Access denied for this account.');
                }

                return {
                    email: verifiedEmail,
                    exp: nowSec_() + Math.min(expiresIn, CONFIG.SESSION_MAX_AGE_SECONDS),
                    name: safeText_(userInfo.name || '', 120),
                    picture: safeImageUrl_(userInfo.picture || '')
                };
            }

            async function validateAndShowDashboard_(payload, token, provider) {
                var email = normalizeEmail_(payload && payload.email);
                if (!email) {
                    throw new Error('Google response did not include an email.');
                }
                if (!isAllowedEmail_(email)) {
                    throw new Error('Access denied. "' + email + '" is not authorized.');
                }

                showStatus('loading', 'Verifying Google session...');

                var verified;
                if (provider === 'id_token') {
                    verified = await verifyIdToken_(token, email);
                } else if (provider === 'access_token') {
                    verified = await verifyAccessToken_(token, email);
                } else {
                    throw new Error('Unsupported authentication provider.');
                }

                var session = buildSession_({
                    email: verified.email,
                    name: payload.name || verified.name || verified.email,
                    picture: payload.picture || verified.picture || '',
                    exp: verified.exp,
                    provider: provider,
                    token: token
                });

                writeStoredSession_(session);
                showStatus('success', 'Welcome, ' + safeText_(session.name, 80) + '. Loading dashboard...');

                setTimeout(function () {
                    clearStatus();
                    showDashboardView(session);
                }, 400);
            }

            async function initializeGoogleSignIn() {
                if (STATE.googleSDKLoaded) return true;

                var sdkReady = await waitForGoogleSDK_(7000);
                if (!sdkReady) {
                    return false;
                }

                google.accounts.id.initialize({
                    client_id: CONFIG.CLIENT_ID,
                    callback: handleCredentialResponse_,
                    auto_select: false,
                    cancel_on_tap_outside: true
                });

                try {
                    google.accounts.id.renderButton(
                        document.getElementById('google-signin-container'),
                        {
                            type: 'standard',
                            theme: 'outline',
                            size: 'large',
                            text: 'signin_with',
                            shape: 'rectangular',
                            logo_alignment: 'left',
                            width: 300
                        }
                    );
                    document.getElementById('custom-google-btn').style.display = 'none';
                } catch (_) {
                    // Keep fallback button visible.
                }

                STATE.tokenClient = google.accounts.oauth2.initTokenClient({
                    client_id: CONFIG.CLIENT_ID,
                    scope: 'email profile',
                    callback: handleTokenResponse_
                });

                STATE.googleSDKLoaded = true;
                return true;
            }

            async function initiateGoogleSignIn() {
                setSignInBusy_(true);
                showStatus('loading', 'Opening Google Sign-In...');

                var ready = STATE.googleSDKLoaded ? true : await initializeGoogleSignIn();
                if (!ready) {
                    showStatus('error', 'Google Sign-In failed to initialize. Please refresh and try again.');
                    setSignInBusy_(false);
                    return;
                }

                google.accounts.id.prompt(function (notification) {
                    if (
                        notification &&
                        (notification.isNotDisplayed() || notification.isSkippedMoment() || notification.isDismissedMoment())
                    ) {
                        if (STATE.tokenClient) {
                            STATE.tokenClient.requestAccessToken({ prompt: 'consent' });
                            return;
                        }
                        showStatus('error', 'Google Sign-In popup could not be opened.');
                    }
                    setSignInBusy_(false);
                });
            }

            async function handleCredentialResponse_(response) {
                try {
                    showStatus('loading', 'Verifying credentials...');
                    if (!response || !response.credential) {
                        throw new Error('Missing Google credential.');
                    }
                    var payload = decodeJwtPayload(response.credential);
                    await validateAndShowDashboard_(payload, response.credential, 'id_token');
                } catch (error) {
                    clearStoredSession_();
                    showStatus('error', error && error.message ? error.message : 'Authentication failed. Please try again.');
                } finally {
                    setSignInBusy_(false);
                }
            }

            async function handleTokenResponse_(response) {
                try {
                    if (!response || response.error) {
                        showStatus('error', 'Sign-in was cancelled.');
                        return;
                    }
                    showStatus('loading', 'Fetching account details...');
                    var userInfo = await fetchJsonWithTimeout_('https://www.googleapis.com/oauth2/v3/userinfo', {
                        headers: { Authorization: 'Bearer ' + response.access_token }
                    });
                    await validateAndShowDashboard_(
                        {
                            email: userInfo.email,
                            name: userInfo.name,
                            picture: userInfo.picture
                        },
                        response.access_token,
                        'access_token'
                    );
                } catch (error) {
                    clearStoredSession_();
                    showStatus('error', error && error.message ? error.message : 'Unable to verify Google account.');
                } finally {
                    setSignInBusy_(false);
                }
            }

            async function restoreValidatedSession_() {
                var session = readStoredSession_();
                if (!isSessionShapeValid_(session)) {
                    clearStoredSession_();
                    return false;
                }
                if (!isSessionFresh_(session)) {
                    clearStoredSession_();
                    return false;
                }
                if (!isAllowedEmail_(session.email)) {
                    clearStoredSession_();
                    return false;
                }

                showStatus('loading', 'Restoring your verified session...');

                try {
                    var verified;
                    if (session.provider === 'id_token') {
                        verified = await verifyIdToken_(session.token, session.email);
                    } else if (session.provider === 'access_token') {
                        verified = await verifyAccessToken_(session.token, session.email);
                    } else {
                        throw new Error('Unsupported stored session type.');
                    }

                    var restored = buildSession_({
                        email: verified.email,
                        name: session.name || verified.name || verified.email,
                        picture: session.picture || verified.picture || '',
                        exp: verified.exp,
                        provider: session.provider,
                        token: session.token
                    });

                    writeStoredSession_(restored);
                    clearStatus();
                    showDashboardView(restored);
                    return true;
                } catch (_) {
                    clearStoredSession_();
                    return false;
                }
            }

            function logout() {
                var existing = readStoredSession_();
                clearStoredSession_();

                if (
                    existing &&
                    existing.provider === 'access_token' &&
                    existing.token &&
                    typeof google !== 'undefined' &&
                    google.accounts &&
                    google.accounts.oauth2 &&
                    typeof google.accounts.oauth2.revoke === 'function'
                ) {
                    try {
                        google.accounts.oauth2.revoke(existing.token, function () { });
                    } catch (_) { }
                }

                if (
                    typeof google !== 'undefined' &&
                    google.accounts &&
                    google.accounts.id &&
                    typeof google.accounts.id.disableAutoSelect === 'function'
                ) {
                    google.accounts.id.disableAutoSelect();
                }

                showLoginView();
                showStatus('success', 'Signed out successfully.');
            }

            window.addEventListener('message', function (event) {
                // origin check
                const origin = String(event.origin || '');
                const isTrusted = TRUSTED_ORIGINS.has(origin);

                if (!isTrusted) {
                    dbg_('Untrusted origin message blocked:', origin);
                    return;
                }

                var frame = document.getElementById('dashboard-frame');
                if (!frame || !frame.contentWindow) return;
                if (event.source !== frame.contentWindow) return;

                var message = event.data;
                if (!message || typeof message !== 'object' || message.type !== 'REQUEST_USER_SESSION') return;

                var session = readStoredSession_();
                var responseData = {
                    type: 'USER_SESSION_RESPONSE',
                    requestId: message.requestId || '0',
                    success: false
                };

                if (isSessionShapeValid_(session) && isSessionFresh_(session)) {
                    responseData = {
                        type: 'USER_SESSION_RESPONSE',
                        requestId: message.requestId || '0',
                        success: true,
                        email: session.email,
                        name: session.name || '',
                        picture: session.picture || '',
                        exp: Number(session.exp || 0),
                        token: session.token
                    };
                    dbg_('Session bridge ACTIVE — propagating identity');
                } else {
                    dbg_('Session bridge FAILED — session invalid or expired');
                    if (session) clearStoredSession_();
                }

                frame.contentWindow.postMessage(responseData, event.origin);
            });

            // Wire controls via addEventListener — no inline onclick handlers, so the
            // CSP no longer needs script-src 'unsafe-inline'. app.js is `defer`, so the
            // DOM is parsed by the time this runs.
            (function wireControls_() {
                var signInBtn = document.getElementById('custom-google-btn');
                if (signInBtn) signInBtn.addEventListener('click', initiateGoogleSignIn);
                var logoutBtn = document.getElementById('logout-btn');
                if (logoutBtn) logoutBtn.addEventListener('click', logout);
            })();

            window.addEventListener('load', function () {
                (async function bootstrap() {
                    showLoginView();
                    showStatus('loading', 'Initializing Google Sign-In...');

                    var initialized = await initializeGoogleSignIn();
                    if (!initialized) {
                        showStatus('error', 'Google Sign-In is unavailable. Please refresh and try again.');
                        return;
                    }

                    var hadSession = !!readStoredSession_();
                    var restored = await restoreValidatedSession_();
                    if (!restored) {
                        if (hadSession) {
                            showStatus('error', 'Your session expired. Please sign in again.');
                        } else {
                            clearStatus();
                        }
                    }
                })().catch(function (error) {
                    clearStoredSession_();
                    showLoginView();
                    showStatus('error', error && error.message ? error.message : 'Unable to initialize app.');
                });
            });
        })();
