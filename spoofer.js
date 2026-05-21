/* ============================================================================
 *  Focus / Visibility Spoofer
 *  ---------------------------------------------------------------------------
 *  A self-contained DevTools-console payload that neutralizes the most common
 *  browser-side focus and visibility detection mechanisms used by anti-cheat,
 *  anti-bot, session-grading, proctoring, and idle-tracking scripts.
 *
 *  Intended use: browser security research, frontend automation testing, and
 *  resilience analysis of pages you are authorized to test.
 *
 *  Usage (Chrome / Edge / Brave DevTools):
 *      1. Open the page (let it fully load).
 *      2. Open DevTools -> Console.
 *      3. Paste this entire file and press Enter.
 *      4. Interact via the global `__focusSpoofer` object.
 *
 *  Quick API:
 *      __focusSpoofer.hookStatus()         // current state of every hook
 *      __focusSpoofer.focusStateMonitor()  // dump spoofed property values
 *      __focusSpoofer.inspectListeners()   // list listeners on `window`
 *      __focusSpoofer.inspectListeners(document)
 *      __focusSpoofer.setMode('aggressive') | setMode('safe')
 *      __focusSpoofer.purgeExisting()
 *      __focusSpoofer.scanIframes()
 *      __focusSpoofer.uninstall()
 *
 *  Design notes:
 *      - Native references are captured BEFORE any patching so that internal
 *        calls cannot be redirected by a hostile page that later monkeypatches
 *        prototypes.
 *      - All replacement functions impersonate their native signature via
 *        Function.prototype.toString -> "function name() { [native code] }".
 *      - Properties are written non-configurable (in default safe mode the
 *        flag is relaxed so the user can uninstall cleanly; aggressive mode
 *        hardens against redefinition).
 *      - Same-origin iframes are patched in their own realm to avoid cross-
 *        realm `this` issues; cross-origin iframes are skipped silently.
 * ========================================================================== */

(() => {
    'use strict';

    /* ---------------------------------------------------------------------- *
     *  Re-entry guard
     * ---------------------------------------------------------------------- */
    if (window.__focusSpoofer && window.__focusSpoofer.installed) {
        console.warn(
            '%c[FocusSpoofer]',
            'color:#fc6;font-weight:bold;',
            'already installed. Call __focusSpoofer.uninstall() first.'
        );
        return window.__focusSpoofer;
    }

    /* ---------------------------------------------------------------------- *
     *  Configuration
     * ---------------------------------------------------------------------- */
    const CONFIG = {
        // 'safe'       -> only the high-signal events (blur, visibilitychange,
        //                 pagehide, freeze, webkit/moz/ms visibilitychange)
        // 'aggressive' -> safe set plus focus, focusin, focusout, pageshow,
        //                 resume; properties redefined non-configurable;
        //                 iframe observer enabled.
        mode: 'safe',

        verbose: true,
        logRemoved: true,
        logBlocked: true,
        logIntercepted: true,
        logOverridden: true,

        spoofProperties: true,
        removeExistingListeners: true,
        blockFutureListeners: true,
        overrideInlineHandlers: true,
        interceptDispatchEvent: true,
        handleIframes: true,
    };

    /* ---------------------------------------------------------------------- *
     *  Target event sets
     * ---------------------------------------------------------------------- */
    const SAFE_EVENTS = new Set([
        'blur',
        'visibilitychange',
        'webkitvisibilitychange',
        'mozvisibilitychange',
        'msvisibilitychange',
        'pagehide',
        'freeze',
    ]);

    const AGGRESSIVE_EVENTS = new Set([
        ...SAFE_EVENTS,
        'focus',
        'focusin',
        'focusout',
        'pageshow',
        'resume',
    ]);

    const activeEvents = () =>
        CONFIG.mode === 'aggressive' ? AGGRESSIVE_EVENTS : SAFE_EVENTS;

    const isTargetEvent = (type) => {
        if (!type) return false;
        return activeEvents().has(String(type).toLowerCase());
    };

    /* ---------------------------------------------------------------------- *
     *  Logger
     * ---------------------------------------------------------------------- */
    const STYLE = 'color:#9cf;font-weight:bold;';
    const stats = {
        removed: 0,
        blocked: 0,
        intercepted: 0,
        overridden: 0,
        errors: 0,
    };

    const log  = (...a) => CONFIG.verbose && console.log ('%c[FocusSpoofer]', STYLE, ...a);
    const warn = (...a) => CONFIG.verbose && console.warn('%c[FocusSpoofer]', STYLE, ...a);
    const err  = (...a) => { stats.errors++; console.error('%c[FocusSpoofer]', STYLE, ...a); };

    /* ---------------------------------------------------------------------- *
     *  Captured native references
     *  These are taken BEFORE any patching so internal calls bypass our own
     *  hooks (and bypass any future hostile patching by the page).
     * ---------------------------------------------------------------------- */
    const native = {
        addEventListener:        EventTarget.prototype.addEventListener,
        removeEventListener:     EventTarget.prototype.removeEventListener,
        dispatchEvent:           EventTarget.prototype.dispatchEvent,
        documentHasFocus:        Document.prototype.hasFocus,

        defineProperty:          Object.defineProperty,
        defineProperties:        Object.defineProperties,
        getOwnPropertyDescriptor:Object.getOwnPropertyDescriptor,

        functionToString:        Function.prototype.toString,

        // DevTools-only - may be undefined when the script is loaded in a
        // non-DevTools context; we feature-detect at call sites.
        getEventListeners: typeof getEventListeners === 'function' ? getEventListeners : null,
    };

    /* ---------------------------------------------------------------------- *
     *  Restore log for uninstall()
     * ---------------------------------------------------------------------- */
    const restorePoints = [];

    function safeDefine(target, prop, descriptor) {
        try {
            const previous = native.getOwnPropertyDescriptor.call(Object, target, prop);
            native.defineProperty.call(Object, target, prop, descriptor);
            restorePoints.push({ target, prop, previous });
            stats.overridden++;
            if (CONFIG.logOverridden) log(`overrode ${String(prop)} on`, target);
            return true;
        } catch (e) {
            err(`failed to define ${String(prop)} on`, target, e);
            return false;
        }
    }

    /* ---------------------------------------------------------------------- *
     *  Disguise our hooks so `fn.toString()` looks native
     * ---------------------------------------------------------------------- */
    function disguise(fn, name) {
        const fakeSource = `function ${name}() { [native code] }`;
        try {
            native.defineProperty.call(Object, fn, 'toString', {
                value: function toString() { return fakeSource; },
                writable: false,
                configurable: true,
                enumerable: false,
            });
            native.defineProperty.call(Object, fn, 'name', {
                value: name,
                writable: false,
                configurable: true,
            });
        } catch (_) { /* non-fatal */ }
        return fn;
    }

    /* ====================================================================== *
     *  MODULE 1 - Remove already-registered listeners
     * ====================================================================== */
    function removeExistingFrom(target, label) {
        if (!native.getEventListeners) {
            warn(
                `getEventListeners() unavailable - cannot enumerate existing ` +
                `listeners on ${label}. Run from DevTools console for full coverage.`
            );
            return 0;
        }
        let removed = 0;
        try {
            const map = native.getEventListeners(target) || {};
            for (const evt of Object.keys(map)) {
                if (!isTargetEvent(evt)) continue;
                // copy because removeEventListener mutates the underlying list
                const entries = map[evt].slice();
                for (const entry of entries) {
                    try {
                        native.removeEventListener.call(
                            target,
                            evt,
                            entry.listener,
                            !!entry.useCapture
                        );
                        removed++;
                        stats.removed++;
                        if (CONFIG.logRemoved) {
                            log(`removed [${label}] ${evt} (capture=${!!entry.useCapture})`, entry.listener);
                        }
                    } catch (e) {
                        err(`could not remove [${label}] ${evt}`, e);
                    }
                }
            }
        } catch (e) {
            err(`getEventListeners() failed on ${label}`, e);
        }
        return removed;
    }

    function purgeExisting() {
        let n = 0;
        n += removeExistingFrom(window,   'window');
        n += removeExistingFrom(document, 'document');
        if (document.documentElement) n += removeExistingFrom(document.documentElement, '<html>');
        if (document.body)            n += removeExistingFrom(document.body,            '<body>');
        log(`purgeExisting(): removed ${n} listener(s) total`);
        return n;
    }

    /* ====================================================================== *
     *  MODULE 2 - Block future listener registration
     * ====================================================================== */

    // Sites sometimes store references to addEventListener and later call
    // remove with the SAME (now-suppressed) function reference. We keep a
    // weak shadow registry so we can pretend the removal worked.
    const shadowRegistry = new WeakMap(); // target -> Map<type, Set<listener>>

    function shadowAdd(target, type, listener) {
        let m = shadowRegistry.get(target);
        if (!m) { m = new Map(); shadowRegistry.set(target, m); }
        let s = m.get(type);
        if (!s) { s = new Set(); m.set(type, s); }
        s.add(listener);
    }
    function shadowRemove(target, type, listener) {
        const m = shadowRegistry.get(target);
        if (!m) return;
        const s = m.get(type);
        if (s) s.delete(listener);
    }

    function patchedAddEventListener(type, listener, options) {
        try {
            if (isTargetEvent(type)) {
                stats.blocked++;
                if (CONFIG.logBlocked) {
                    log(`blocked addEventListener("${type}")`, listener, 'on', this);
                }
                shadowAdd(this, String(type).toLowerCase(), listener);
                return undefined;
            }
        } catch (e) {
            err('addEventListener hook error', e);
        }
        return native.addEventListener.call(this, type, listener, options);
    }

    function patchedRemoveEventListener(type, listener, options) {
        try {
            if (isTargetEvent(type)) {
                shadowRemove(this, String(type).toLowerCase(), listener);
                return undefined;
            }
        } catch (e) {
            err('removeEventListener hook error', e);
        }
        return native.removeEventListener.call(this, type, listener, options);
    }

    function installListenerPatches() {
        disguise(patchedAddEventListener,    'addEventListener');
        disguise(patchedRemoveEventListener, 'removeEventListener');

        const hardenCfg = CONFIG.mode === 'aggressive' ? false : true;

        safeDefine(EventTarget.prototype, 'addEventListener', {
            value: patchedAddEventListener,
            writable: false,
            configurable: hardenCfg,
            enumerable: false,
        });
        safeDefine(EventTarget.prototype, 'removeEventListener', {
            value: patchedRemoveEventListener,
            writable: false,
            configurable: hardenCfg,
            enumerable: false,
        });
        log('hooked EventTarget.prototype.{add,remove}EventListener');
    }

    /* ====================================================================== *
     *  MODULE 3 - Neutralize inline handlers (onblur, onvisibilitychange, ...)
     * ====================================================================== */
    function installInlineHandlerBlocks() {
        const targets = [
            {
                target: window,
                props: ['onblur', 'onfocus', 'onpagehide', 'onpageshow', 'onvisibilitychange'],
            },
            {
                target: document,
                props: [
                    'onvisibilitychange',
                    'onwebkitvisibilitychange',
                    'onblur',
                    'onfocus',
                    'onfreeze',
                    'onresume',
                ],
            },
        ];

        const hardenCfg = CONFIG.mode === 'aggressive' ? false : true;

        for (const { target, props } of targets) {
            for (const p of props) {
                // strip whatever was already assigned
                try { target[p] = null; } catch (_) { /* ignore */ }

                safeDefine(target, p, {
                    get() { return null; },
                    set(v) {
                        stats.blocked++;
                        if (CONFIG.logBlocked) {
                            log(`blocked inline assignment ${p} =`, v);
                        }
                    },
                    configurable: hardenCfg,
                    enumerable: true,
                });
            }
        }
        log('inline event handlers neutralized');
    }

    /* ====================================================================== *
     *  MODULE 4 - Property spoofing (hasFocus / hidden / visibilityState)
     * ====================================================================== */
    function installPropertySpoof() {
        const hardenCfg = CONFIG.mode === 'aggressive' ? false : true;

        const fakeHasFocus = disguise(function hasFocus() { return true; }, 'hasFocus');

        safeDefine(Document.prototype, 'hasFocus', {
            value: fakeHasFocus,
            writable: false,
            configurable: hardenCfg,
            enumerable: false,
        });

        const visibleGetter = { get() { return 'visible'; }, configurable: hardenCfg, enumerable: true };
        const hiddenGetter  = { get() { return false;     }, configurable: hardenCfg, enumerable: true };

        safeDefine(Document.prototype, 'hidden',                 hiddenGetter);
        safeDefine(Document.prototype, 'webkitHidden',           hiddenGetter);
        safeDefine(Document.prototype, 'mozHidden',              hiddenGetter);
        safeDefine(Document.prototype, 'msHidden',               hiddenGetter);

        safeDefine(Document.prototype, 'visibilityState',        visibleGetter);
        safeDefine(Document.prototype, 'webkitVisibilityState',  visibleGetter);
        safeDefine(Document.prototype, 'mozVisibilityState',     visibleGetter);
        safeDefine(Document.prototype, 'msVisibilityState',      visibleGetter);

        // Page Lifecycle flags some sites read defensively
        safeDefine(Document.prototype, 'wasDiscarded', {
            get() { return false; }, configurable: true, enumerable: true,
        });
        safeDefine(Document.prototype, 'prerendering', {
            get() { return false; }, configurable: true, enumerable: true,
        });

        log('document focus/visibility/lifecycle properties spoofed');
    }

    /* ====================================================================== *
     *  MODULE 5 - Intercept dispatchEvent
     *  Some libraries synthesize their own blur / visibilitychange events.
     * ====================================================================== */
    function patchedDispatchEvent(event) {
        try {
            const t = event && event.type ? String(event.type).toLowerCase() : '';
            if (t && isTargetEvent(t)) {
                stats.intercepted++;
                if (CONFIG.logIntercepted) {
                    log(`intercepted dispatchEvent("${t}") on`, this);
                }
                return true;
            }
        } catch (e) {
            err('dispatchEvent hook error', e);
        }
        return native.dispatchEvent.call(this, event);
    }

    function installDispatchEventInterceptor() {
        disguise(patchedDispatchEvent, 'dispatchEvent');
        safeDefine(EventTarget.prototype, 'dispatchEvent', {
            value: patchedDispatchEvent,
            writable: false,
            configurable: CONFIG.mode === 'aggressive' ? false : true,
            enumerable: false,
        });
        log('hooked EventTarget.prototype.dispatchEvent');
    }

    /* ====================================================================== *
     *  MODULE 6 - Iframe handling
     *  Same-origin iframes get their own per-realm hooks so cross-realm
     *  `this` doesn't break the natives we captured in the parent realm.
     *  Cross-origin iframes are skipped (we cannot legally touch them).
     * ====================================================================== */
    function applyToIframe(iframe) {
        let cw;
        try { cw = iframe.contentWindow; } catch (_) { return false; }
        if (!cw) return false;

        // same-origin probe
        try { void cw.location.href; } catch (_) { return false; }

        try {
            // Per-realm captured natives
            const cNative = {
                add:      cw.EventTarget.prototype.addEventListener,
                remove:   cw.EventTarget.prototype.removeEventListener,
                dispatch: cw.EventTarget.prototype.dispatchEvent,
            };

            function frameAdd(type, listener, options) {
                if (isTargetEvent(type)) {
                    stats.blocked++;
                    if (CONFIG.logBlocked) log(`[iframe] blocked addEventListener("${type}")`);
                    return;
                }
                return cNative.add.call(this, type, listener, options);
            }
            function frameRemove(type, listener, options) {
                if (isTargetEvent(type)) return;
                return cNative.remove.call(this, type, listener, options);
            }
            function frameDispatch(event) {
                if (event && isTargetEvent(event.type)) {
                    stats.intercepted++;
                    if (CONFIG.logIntercepted) log(`[iframe] intercepted dispatch("${event.type}")`);
                    return true;
                }
                return cNative.dispatch.call(this, event);
            }

            disguise(frameAdd,      'addEventListener');
            disguise(frameRemove,   'removeEventListener');
            disguise(frameDispatch, 'dispatchEvent');

            cw.Object.defineProperty(cw.EventTarget.prototype, 'addEventListener',    { value: frameAdd,      writable: false, configurable: true });
            cw.Object.defineProperty(cw.EventTarget.prototype, 'removeEventListener', { value: frameRemove,   writable: false, configurable: true });
            cw.Object.defineProperty(cw.EventTarget.prototype, 'dispatchEvent',       { value: frameDispatch, writable: false, configurable: true });

            const dp = cw.Document.prototype;
            cw.Object.defineProperty(dp, 'hidden',          { get: () => false,     configurable: true });
            cw.Object.defineProperty(dp, 'visibilityState', { get: () => 'visible', configurable: true });
            cw.Object.defineProperty(dp, 'hasFocus',        { value: () => true,    configurable: true });

            // strip already-registered listeners inside the frame
            if (native.getEventListeners) {
                try {
                    removeExistingFrom(cw,          'iframe.window');
                    removeExistingFrom(cw.document, 'iframe.document');
                } catch (_) { /* ignore */ }
            }

            log('applied spoofer to iframe', iframe.src || iframe.srcdoc ? '(srcdoc)' : '(blank)');
            return true;
        } catch (e) {
            err('iframe apply failed', e);
            return false;
        }
    }

    function scanIframes() {
        const frames = document.querySelectorAll('iframe');
        let ok = 0;
        frames.forEach((f) => { if (applyToIframe(f)) ok++; });
        log(`scanIframes(): patched ${ok}/${frames.length} same-origin iframe(s)`);
        return ok;
    }

    let iframeObserver = null;
    function observeIframes() {
        if (iframeObserver) return;
        iframeObserver = new MutationObserver((muts) => {
            for (const m of muts) {
                for (const node of m.addedNodes) {
                    if (!node || node.nodeType !== 1) continue;
                    if (node.tagName === 'IFRAME') {
                        applyToIframe(node);
                        node.addEventListener('load', () => applyToIframe(node), { once: true });
                    } else if (node.querySelectorAll) {
                        node.querySelectorAll('iframe').forEach((f) => {
                            applyToIframe(f);
                            f.addEventListener('load', () => applyToIframe(f), { once: true });
                        });
                    }
                }
            }
        });
        iframeObserver.observe(document.documentElement || document, {
            childList: true,
            subtree: true,
        });
        log('iframe MutationObserver active');
    }

    /* ====================================================================== *
     *  Debug utilities
     * ====================================================================== */
    function inspectListeners(target) {
        target = target || window;
        if (!native.getEventListeners) {
            warn('inspectListeners requires DevTools (getEventListeners is unavailable).');
            return null;
        }
        const map = native.getEventListeners(target) || {};
        const rows = Object.entries(map).map(([type, entries]) => ({
            type,
            count: entries.length,
            flagged: isTargetEvent(type),
            capture: entries.some((e) => e.useCapture),
            passive: entries.some((e) => e.passive),
        }));
        console.group(`Listeners on`, target);
        console.table(rows);
        console.groupEnd();
        return map;
    }

    function focusStateMonitor() {
        const snapshot = {
            'document.hasFocus()':            (() => { try { return document.hasFocus(); } catch (e) { return e.message; } })(),
            'document.hidden':                document.hidden,
            'document.visibilityState':       document.visibilityState,
            'document.webkitHidden':          document.webkitHidden,
            'document.webkitVisibilityState': document.webkitVisibilityState,
            'document.wasDiscarded':          document.wasDiscarded,
        };
        console.group('Focus / Visibility snapshot');
        console.table(snapshot);
        console.groupEnd();
        return snapshot;
    }

    function hookStatus() {
        const status = {
            installed:                    api.installed,
            mode:                         CONFIG.mode,
            addEventListener_hooked:      EventTarget.prototype.addEventListener    === patchedAddEventListener,
            removeEventListener_hooked:   EventTarget.prototype.removeEventListener === patchedRemoveEventListener,
            dispatchEvent_hooked:         EventTarget.prototype.dispatchEvent       === patchedDispatchEvent,
            hasFocus_spoofed:             Document.prototype.hasFocus               !== native.documentHasFocus,
            hidden_current_value:         document.hidden,
            visibilityState_current_value:document.visibilityState,
        };
        console.group('FocusSpoofer status');
        console.table(status);
        console.table(stats);
        console.groupEnd();
        return { status, stats: { ...stats } };
    }

    /* ====================================================================== *
     *  Uninstall
     * ====================================================================== */
    function uninstall() {
        // restore in reverse order
        for (let i = restorePoints.length - 1; i >= 0; i--) {
            const { target, prop, previous } = restorePoints[i];
            try {
                if (previous) {
                    native.defineProperty.call(Object, target, prop, previous);
                } else {
                    delete target[prop];
                }
            } catch (e) {
                err(`uninstall: failed to restore ${String(prop)}`, e);
            }
        }
        restorePoints.length = 0;

        if (iframeObserver) {
            try { iframeObserver.disconnect(); } catch (_) {}
            iframeObserver = null;
        }

        api.installed = false;
        log('uninstalled. (Listeners that were removed are NOT re-attached.)');
    }

    /* ====================================================================== *
     *  Install orchestrator
     * ====================================================================== */
    function install() {
        if (api.installed) { warn('install(): already installed'); return api; }
        log(`installing in ${CONFIG.mode.toUpperCase()} mode`);

        try {
            if (CONFIG.spoofProperties)         installPropertySpoof();
            if (CONFIG.removeExistingListeners) purgeExisting();
            if (CONFIG.blockFutureListeners)    installListenerPatches();
            if (CONFIG.overrideInlineHandlers)  installInlineHandlerBlocks();
            if (CONFIG.interceptDispatchEvent)  installDispatchEventInterceptor();
            if (CONFIG.handleIframes) {
                scanIframes();
                if (CONFIG.mode === 'aggressive') observeIframes();
            }
            api.installed = true;
            log('install complete. See __focusSpoofer.hookStatus() for details.');
        } catch (e) {
            err('install() failed', e);
        }

        return api;
    }

    /* ====================================================================== *
     *  Public API
     * ====================================================================== */
    const api = {
        installed: false,
        config: CONFIG,
        stats,

        install,
        uninstall,

        setMode(m) {
            if (m !== 'safe' && m !== 'aggressive') {
                warn(`setMode(): expected 'safe' | 'aggressive', got`, m);
                return;
            }
            CONFIG.mode = m;
            log(`mode -> ${m}`);
            // re-purge so the newly active set is enforced against listeners
            // that registered between the previous mode and now
            if (api.installed) purgeExisting();
        },

        purgeExisting,
        scanIframes,
        observeIframes,

        inspectListeners,
        focusStateMonitor,
        hookStatus,

        // exposed for advanced debugging
        _native: native,
        _shadowRegistry: shadowRegistry,
        _restorePoints: restorePoints,
        _events: { SAFE_EVENTS, AGGRESSIVE_EVENTS },
    };

    // Attach to window with a non-enumerable descriptor so it doesn't show up
    // in for...in / Object.keys() scans the page might run.
    try {
        native.defineProperty.call(Object, window, '__focusSpoofer', {
            value: api,
            writable: false,
            configurable: true,
            enumerable: false,
        });
    } catch (_) {
        window.__focusSpoofer = api;
    }

    install();
    return api;
})();
