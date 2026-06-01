// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Risk Queue Console (G-A3) - client logic.
//
// External script (no inline) so the page loads under a script-src 'self'
// Content-Security-Policy. It reads the prioritized queue, applies operator
// actions, and live-updates from the gateway event feed.
//
// Claims discipline: this console surfaces actions for decision. Resolving an
// item records the decision and supports evidence for who decided what and
// when. It does not record that the downstream effect was carried out - that
// is enforced at the edge (short-lived tokens, sink verification, revocation
// epochs), shown per action as "enforced by".

(function () {
  'use strict';

  var API_BASE = '/api/v1';
  // The console runs same-origin with the gateway; the auth cookie or the
  // portal's bearer header is attached by the embedding page. Requests use
  // credentials so the gateway authMiddleware can attach req.tenant.
  var FETCH_OPTS = { credentials: 'same-origin', headers: { Accept: 'application/json' } };

  var ACTION_LABELS = {
    approve: 'Approve',
    deny: 'Deny',
    freeze: 'Freeze',
    open_ticket: 'Open ticket',
    export_bundle: 'Export bundle',
    edit_policy: 'Edit policy',
    escalate: 'Escalate'
  };

  // Which actions make sense for which item kind. The server validates the
  // action regardless; this only trims the buttons shown to the operator.
  var ACTIONS_BY_KIND = {
    needs_approval: ['approve', 'deny', 'escalate', 'open_ticket'],
    revocation_stale: ['freeze', 'escalate', 'open_ticket', 'export_bundle'],
    denied_high_risk_action: ['freeze', 'edit_policy', 'open_ticket', 'export_bundle'],
    new_destination: ['approve', 'deny', 'edit_policy'],
    missing_sink_confirmation: ['open_ticket', 'export_bundle', 'escalate'],
    repeated_denials: ['freeze', 'edit_policy', 'open_ticket'],
    agent_outside_baseline: ['freeze', 'escalate', 'export_bundle', 'open_ticket']
  };

  var els = {
    list: document.getElementById('queue-list'),
    empty: document.getElementById('empty-state'),
    count: document.getElementById('item-count'),
    live: document.getElementById('live-status'),
    refresh: document.getElementById('refresh-btn'),
    oversight: document.getElementById('oversight'),
    oversightList: document.getElementById('oversight-list'),
    template: document.getElementById('item-template')
  };

  function setLive(state, text) {
    els.live.setAttribute('data-state', state);
    els.live.textContent = 'live feed: ' + text;
  }

  function ageLabel(createdAt) {
    var ms = Date.now() - new Date(createdAt).getTime();
    if (!isFinite(ms) || ms < 0) ms = 0;
    var mins = Math.floor(ms / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + 'm ago';
    var hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + 'h ago';
    return Math.floor(hrs / 24) + 'd ago';
  }

  function renderItem(item) {
    var node = els.template.content.firstElementChild.cloneNode(true);
    node.setAttribute('data-severity', item.severity);
    node.setAttribute('data-id', item.id);
    node.querySelector('.severity').textContent = item.severity;
    node.querySelector('.kind').textContent = String(item.kind).replace(/_/g, ' ');
    node.querySelector('.summary').textContent = item.summary;
    node.querySelector('.agent').textContent = item.agent_id ? ('agent: ' + item.agent_id) : '';
    node.querySelector('.subject').textContent = item.subject ? ('subject: ' + item.subject) : '';
    node.querySelector('.age').textContent = ageLabel(item.created_at);

    var actionsEl = node.querySelector('.item-actions');
    var actions = ACTIONS_BY_KIND[item.kind] || ['open_ticket'];
    actions.forEach(function (action) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = ACTION_LABELS[action] || action;
      btn.setAttribute('data-action', action);
      btn.addEventListener('click', function () { applyAction(item.id, action, node); });
      actionsEl.appendChild(btn);
    });
    return node;
  }

  function renderQueue(items) {
    els.list.textContent = '';
    if (!items || items.length === 0) {
      els.empty.hidden = false;
      els.count.textContent = '0 open';
      return;
    }
    els.empty.hidden = true;
    els.count.textContent = items.length + ' open';
    items.forEach(function (item) { els.list.appendChild(renderItem(item)); });
  }

  function renderOversight(flags) {
    if (!flags || flags.length === 0) { els.oversight.hidden = true; return; }
    els.oversight.hidden = false;
    els.oversightList.textContent = '';
    flags.forEach(function (f) {
      var li = document.createElement('li');
      li.textContent = (f.fatigue_type || 'signal') + ': ' + (f.description || '');
      els.oversightList.appendChild(li);
    });
  }

  function load() {
    els.refresh.disabled = true;
    fetch(API_BASE + '/risk-queue', FETCH_OPTS)
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (data) {
        renderQueue(data.items || []);
        renderOversight(data.operator_oversight_flags || []);
      })
      .catch(function () { setLive('error', 'could not load queue'); })
      .then(function () { els.refresh.disabled = false; });
  }

  function applyAction(id, action, node) {
    var buttons = node.querySelectorAll('button');
    buttons.forEach(function (b) { b.disabled = true; });
    fetch(API_BASE + '/risk-queue/' + encodeURIComponent(id) + '/action', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ action: action })
    })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function () {
        // Resolved: remove the item locally; the live feed also broadcasts this.
        node.parentNode && node.parentNode.removeChild(node);
        load();
      })
      .catch(function () {
        buttons.forEach(function (b) { b.disabled = false; });
      });
  }

  // Live updates from the gateway event feed. New risk_flagged / approval_*
  // events refresh the queue in place. This is the same SSE surface the event
  // spine (G-A1) will back; the client contract is the event type names.
  function connectFeed() {
    if (typeof EventSource === 'undefined') { setLive('off', 'not supported'); return; }
    var types = 'risk_flagged,approval_required,approval_resolved';
    var src = new EventSource(API_BASE + '/events/stream?types=' + types);
    src.onopen = function () { setLive('on', 'connected'); };
    src.onerror = function () { setLive('error', 'reconnecting'); };
    var refresh = function () { load(); };
    ['risk_flagged', 'approval_required', 'approval_resolved'].forEach(function (t) {
      src.addEventListener(t, refresh);
    });
  }

  els.refresh.addEventListener('click', load);
  load();
  connectFeed();
})();
