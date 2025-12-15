/**
 * Akula Node - v3.2.1 (Full Spectrum)
 * Core Detection Engine: Static, Dynamic, Global, and Heuristic.
 */
(function () {
  'use strict';

  const SCRIPT_TAG = document.currentScript;
  const CLIENT_ID = SCRIPT_TAG ? SCRIPT_TAG.getAttribute('data-client-id') : null;
  // Fallback to local origin if src is missing (for local testing)
  const SRC_URL = SCRIPT_TAG ? SCRIPT_TAG.src : window.location.origin;
  const BASE_URL = SRC_URL.substring(0, SRC_URL.lastIndexOf('/')); 
  const LOG_PREFIX = 'Akula Node:';

  if (!CLIENT_ID) { console.warn(`${LOG_PREFIX} Missing Client ID`); return; }

  let config = {};
  let signatures = {};
  let reportBuffer = [];
  const SESSION_ID = crypto.randomUUID();
  const CACHE_KEY_SIGS = 'akula_node_sig_v3.2';
  
  const SAFETY_REGEX = /checkout|payment|order-received|paypal|stripe/i;

  // <ADDITION: STATE TRACKER>
  let reportedGlobals = new Set(); 

  async function init() {
    try {
      // 1. Fetch Config
      const configRes = await fetch(`${BASE_URL}/configs/config-client-${CLIENT_ID}.json`);
      if (!configRes.ok) throw new Error('Config Unreachable');
      config = await configRes.json();

      if (!config.enabled) { console.log(`${LOG_PREFIX} Disabled.`); return; }
      
      // Safety Check
      if (SAFETY_REGEX.test(window.location.href) && config.mode !== 'active-checkout') {
          console.log(`${LOG_PREFIX} Standing By (Sensitive Zone)`);
          return;
      }

      // 2. Load Signatures
      await loadSignatures();

      // 3. Engage Layers
      if (config.layers.static) startStaticLayer();
      if (config.layers.behavioral) startBehavioralHooks();

      // 4. Reporting Uplink
      if (config.reporting && config.reporting.endpoint) {
        // NOTE: The report interval is now managed by flushReports() internal logic
        // We keep this to ensure at least a flush every 10 seconds, even if no events happened.
        setInterval(flushReports, config.reporting.batchIntervalMs || 10000); 
      }
      
      // 5. Run Periodic Checks (Globals & Bait)
      runAdBlockerDetection();
      setInterval(checkGlobalVars, 2000); // Check window vars every 2s

    } catch (e) { 
      console.warn(`${LOG_PREFIX} Init Error`, e);
    }
  }

  async function loadSignatures() {
    const now = Date.now();
    const cached = localStorage.getItem(CACHE_KEY_SIGS);
    
    // Cache for 3 hours
    if (cached) {
      const parsed = JSON.parse(cached);
      if (now - parsed.ts < 10800000) { 
        signatures = parsed.data;
        return;
      }
    }

    const res = await fetch(`${BASE_URL}/signatures.json`);
    signatures = await res.json();
    localStorage.setItem(CACHE_KEY_SIGS, JSON.stringify({ ts: now, data: signatures }));
  }

  // --- LAYERS ---
  function startStaticLayer() {
    const observer = new MutationObserver(mutations => {
      mutations.forEach(m => {
        m.addedNodes.forEach(node => {
          if (node.nodeType === 1) scanNode(node);
        });
      });
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    document.querySelectorAll('*').forEach(scanNode);
  }

  function startBehavioralHooks() {
    const originalAttachShadow = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function(init) {
      const shadowRoot = originalAttachShadow.apply(this, arguments);
      const shadowObserver = new MutationObserver(mutations => {
        mutations.forEach(m => m.addedNodes.forEach(n => {
            if(n.nodeType === 1) scanNode(n);
        }));
      });
      shadowObserver.observe(shadowRoot, { childList: true, subtree: true });
      return shadowRoot;
    };
  }
  
  // <MODIFIED: Global Variable Check with Whitelist>
  function checkGlobalVars() {
      if (!signatures.patterns || !signatures.patterns.globalVars) return;
      
      // Get whitelist from config (handle case where 'globals' array is missing)
      const whitelistedGlobals = config.whitelist && config.whitelist.globals ? config.whitelist.globals : [];

      signatures.patterns.globalVars.forEach(varName => {
          // 1. Check if the global is explicitly whitelisted by the client
          if (whitelistedGlobals.includes(varName)) return; 
          
          // 2. Only report if it exists AND we haven't reported it yet
          if ((window.hasOwnProperty(varName) || window[varName]) && !reportedGlobals.has(varName)) {
              reportedGlobals.add(varName); // Remember we saw it
              report('global_var_detected', { detail: varName }, 'log');
          }
      });
  }

  function runAdBlockerDetection() {
      if (!signatures.patterns.adBlockBaitClasses) return;
      const baitDiv = document.createElement('div');
      baitDiv.className = signatures.patterns.adBlockBaitClasses.join(' '); 
      baitDiv.style.cssText = 'width: 1px !important; height: 1px !important; position: absolute !important; left: -9999px !important;';
      document.body.appendChild(baitDiv);
      
      setTimeout(() => {
          const isBlocked = baitDiv.offsetHeight === 0 || baitDiv.style.display === 'none';
          if (isBlocked) report('extension_adblock_detected', { detail: 'Bait Hidden' }, 'warn');
          baitDiv.remove();
      }, 100); 
  }

  // --- SCANNER ---
  function scanNode(node) {
    if (isWhitelisted(node)) return;

    // 1. Check Script Sources (NOTE: Whitelisting for scripts is now done in isWhitelisted)
    // Removed old whitelisting logic here.

    if (node.tagName === 'SCRIPT' && node.src) {
      if (signatures.patterns.scriptSrcPatterns.some(s => node.src.includes(s))) {
        eliminate(node, 'script_src_match', node.src);
        return;
      }
    }

    // 2. Check Iframe Sources (NOTE: Whitelisting for iframes is now done in isWhitelisted)
    // Removed old whitelisting logic here.
    if (node.tagName === 'IFRAME' && node.src) {
        if (signatures.patterns.iframeSrcPatterns.some(s => node.src.includes(s))) {
          eliminate(node, 'iframe_src_match', node.src);
          return;
        }
    }

    // 3. Check ID (Raw string match for O(1) speed)
    const id = node.id;
    if (id && signatures.patterns.ids.includes(id)) {
      eliminate(node, 'id_match', id);
      return;
    }

    // 4. Check Class
    const cls = typeof node.className === 'string' ? node.className : '';
    if (cls && signatures.patterns.classNames.some(c => cls.includes(c))) {
      eliminate(node, 'class_match', cls);
      return;
    }
    
    // 5. Heuristic Overlay (High Z-Index + Text)
    if (config.layers.domShield) {
      const style = window.getComputedStyle(node);
      if ((style.position === 'fixed' || style.position === 'absolute') && parseInt(style.zIndex) > 2000) {
        const text = node.innerText || '';
        if (signatures.patterns.textPatterns.some(t => text.includes(t))) {
          eliminate(node, 'heuristic_overlay', text.substring(0, 50));
        }
      }
    }
  }

  // <REPLACEMENT: Whitelist Check with Parent Traversal and Script/Iframe Source Check>
  function isWhitelisted(node) {
      if (!config.whitelist) return false;
      
      const whitelist = config.whitelist;

      // Check current node and all its ancestors (Critical Fix 1: Parent Check)
      let current = node;
      while (current) {
          // 1. Check Selector Whitelist (for #cart-drawer, .shopify-payment-button, or parent modals)
          if (whitelist.selectors && whitelist.selectors.some(s => current.matches && current.matches(s))) {
              return true;
          }
          current = current.parentElement;
      }

      // 2. Check Script/Iframe Source Whitelist (Critical Fix 2)
      // This is a check on the *node itself*, not its parents.
      if (node.tagName === 'SCRIPT' && node.src) {
          if (whitelist.scriptSrc && whitelist.scriptSrc.some(h => node.src.includes(h))) return true;
      }

      if (node.tagName === 'IFRAME' && node.src) {
          // Already in your original function, but now structured with the script check
          if (whitelist.iframeHosts && whitelist.iframeHosts.some(h => node.src.includes(h))) return true;
      }
      
      return false;
  }
  // </REPLACEMENT: Whitelist Check with Parent Traversal and Script/Iframe Source Check>


  function eliminate(node, type, detail) {
    if (config.mode === 'report-only') {
      report(type, { detail, tag: node.tagName }, 'log');
      // VISUAL DEBUG: Remove this line in production
      return;
    }
    try {
      node.remove();
      report(type, { detail, tag: node.tagName }, 'blocked');
    } catch(e) {}
  }

  function report(type, details, action) {
    reportBuffer.push({
      ts: Date.now(),
      session_id: SESSION_ID,
      type, details, action,
      url: window.location.href
    });
    // <IMPROVEMENT: Batch Reporting Threshold>
    // Flush reports immediately if the buffer is full (e.g., 5+ events)
    // or if the interval timer (in init) triggers.
    if (reportBuffer.length >= 5) flushReports(); 
    // </IMPROVEMENT: Batch Reporting Threshold>
  }

  function flushReports() {
    if (!reportBuffer.length || !config.reporting.endpoint) return;
    const data = JSON.stringify({ clientId: CLIENT_ID, events: reportBuffer });
    
    if (navigator.sendBeacon) {
      navigator.sendBeacon(config.reporting.endpoint, data);
    } else {
      fetch(config.reporting.endpoint, { method: 'POST', body: data, keepalive: true }).catch(()=>{});
    }
    reportBuffer = [];
  }

  init();
})();