import { sb } from './sb';
import { renderCircuitBoard } from './CircuitBoard';
import { parseCvssVector, deriveFromScore, type CvssParseResult } from './cvss';

export type Status = 'act' | 'plan' | 'mon' | 'risk';

export function statusFor(score: number | null | undefined, isKev: boolean | null | undefined): Status {
  if (isKev) return 'act';
  const s = score ?? 0;
  if (s >= 70) return 'act';
  if (s >= 50) return 'plan';
  if (s >= 25) return 'mon';
  return 'risk';
}

const STATUS_LABEL: Record<Status, string> = {
  act: 'Act Now',
  plan: 'Plan Patch',
  mon: 'Monitor',
  risk: 'Low Risk',
};

export function statusLabel(s: Status) { return STATUS_LABEL[s]; }

function escapeHtml(s: any): string {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] || c));
}

function truncate(s: any, n: number): string {
  const str = String(s ?? '');
  return str.length > n ? str.slice(0, n - 1) + '…' : str;
}

function firstVendor(v: any): string {
  const list = v?.vendors;
  if (Array.isArray(list) && list.length) return String(list[0]);
  return 'General';
}

function relativeWhen(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diffSec < 3600) return 'Just now';
  const hours = Math.floor(diffSec / 3600);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

export function renderAdvisoryCard(r: any, isActive: boolean = false, index: number = 0): string {
  const v = r.vuln || {};
  const status = statusFor(r.score, v.is_kev);
  const vendor = firstVendor(v);
  const title = v.cve_id ? `${vendor} Advisory (${v.cve_id})` : (r.cve_id || 'Security Advisory');
  const desc = v.description || r.rationale || 'No description available.';
  const cve = escapeHtml(r.cve_id);
  const when = relativeWhen(v.last_updated_at || r.computed_at);
  
  const badges: string[] = [];
  if (v.is_kev) badges.push(`<span class="badge-kev">CISA KEV</span>`);
  if (v.exploited_in_wild) badges.push(`<span class="badge-wild">EXPLOITED IN WILD</span>`);
  if (v.poc_public) badges.push(`<span class="badge-poc">POC PUBLIC</span>`);

  const fixText = v.is_kev ? '<span class="no-fix">No fix available</span>' : '<span class="fix-available">Fix available</span>';
  const activeClass = isActive ? 'is-active' : '';
  const delayMs = Math.min(index * 25, 400);

  return `
    <article class="advisory-card ${activeClass}" data-cve="${cve}" style="--delay: ${delayMs}ms">
      <div class="card-top-row">
        <span class="card-urgency-badge ${status}">[ ${statusLabel(status).toUpperCase()} ]</span>
        <span class="card-domain-badge ${r.domain === 'OT' ? 'badge-domain-ot' : 'badge-domain-it'}">${escapeHtml(r.domain || 'IT')}</span>
        <div class="card-badges">${badges.join('')}</div>
      </div>
      <div class="card-title">${escapeHtml(truncate(desc.length > 30 ? desc.slice(0, 75) : title, 80))}</div>
      <div class="card-summary">${escapeHtml(truncate(desc, 160))}</div>
      <div class="card-tags">
        <span class="vendor-tag">${escapeHtml(vendor)}</span>
        ${(v.products || []).slice(0, 2).map((p: string) => `<span class="vendor-tag">${escapeHtml(p)}</span>`).join('')}
      </div>
      <div class="card-footer">
        <div class="card-footer-fix">${fixText} · <strong class="card-cve-mono">${cve}</strong></div>
        <div class="card-footer-meta">${v.cvss_v3_score != null ? `<span class="card-score-badge">CVSS ${v.cvss_v3_score.toFixed(1)}</span>` : ''} <span>${escapeHtml(when)}</span></div>
      </div>
    </article>
  `;
}

export function renderFeedCards(container: HTMLElement, rows: any[], activeCveId: string | null, onCardClick: (cve: string) => void) {
  if (!rows || rows.length === 0) {
    container.innerHTML = `<div class="detail-placeholder">No vulnerabilities found for the selected filters.</div>`;
    return;
  }

  container.innerHTML = rows.slice(0, 150).map((r, i) => renderAdvisoryCard(r, r.cve_id === activeCveId, i)).join('');

  container.querySelectorAll<HTMLElement>('.advisory-card').forEach(card => {
    card.addEventListener('click', () => {
      const cve = card.dataset.cve;
      if (cve) onCardClick(cve);
    });
  });
}

export function renderDetailPanel(container: HTMLElement, row: any | null, onClose: () => void) {
  const closeBtnSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>`;
  const shareIcon = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>`;
  const linkIcon = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`;

  if (!row) {
    container.innerHTML = `
      <div class="drawer-header-bar">
        <div class="drawer-header-top">
          <div class="drawer-title-block">
            <span class="drawer-cve-id">SENTINEL-BENCH</span>
            <span class="drawer-title">Vulnerability Analysis</span>
          </div>
          <button class="drawer-close-btn" id="btn-close-drawer">${closeBtnSvg}</button>
        </div>
      </div>
      <div class="drawer-body">
        <div class="detail-placeholder">Select a vulnerability from the feed to view its full analysis.</div>
      </div>
    `;
    document.getElementById('btn-close-drawer')?.addEventListener('click', onClose);
    return;
  }

  const v = row.vuln || {};
  const status = statusFor(row.score, v.is_kev);
  const statusName = statusLabel(status);
  const statusPillClass = `pill-${status}`;
  const cvss = v.cvss_v3_score != null ? v.cvss_v3_score.toFixed(1) : null;
  const epss = v.epss_score != null ? (v.epss_score * 100).toFixed(1) + '%' : null;
  const vendor = firstVendor(v);
  const desc = v.description || row.rationale || 'No detailed vulnerability information available.';
  const when = relativeWhen(v.last_updated_at || row.computed_at);
  const fullDate = v.last_updated_at || row.computed_at
    ? new Date(v.last_updated_at || row.computed_at).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
    : '—';

  // CVSS vector: prefer the real vector; if missing or unparseable, derive from score.
  // ponytail: cvss_v3_vector isn't currently exposed by the API, so the derived fallback
  // is the path that runs in production. The parser is wired and will activate as soon
  // as the API starts returning the vector.
  const cvssParsed: CvssParseResult = parseCvssVector(v.cvss_v3_vector);
  const cvssMetrics = cvssParsed.valid
    ? cvssParsed
    : deriveFromScore(v.cvss_v3_score);
  const attackVector = cvssParsed.attackVector ?? cvssMetrics.attackVector ?? '—';
  const authRequired = cvssParsed.authRequired ?? cvssMetrics.authRequired ?? '—';
  const complexity = cvssParsed.complexity ?? cvssMetrics.complexity ?? '—';
  const userInteraction = cvssParsed.userInteraction ?? cvssMetrics.userInteraction ?? '—';

  // Icons (use currentColor so they theme with the drawer)
  const globeIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>`;
  const keyIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 5.3-5.3"/><path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4.1a1 1 0 0 0-1.4 0l-2.1 2.1a1 1 0 0 0 0 1.3"/></svg>`;
  const gearIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`;
  const userIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`;

  // Helper for refs — adapts to either {url, source} or string-only inputs.
  const refsList: Array<{ url: string; source?: string }> = Array.isArray(v.refs)
    ? v.refs.map((r: any) => typeof r === 'string' ? { url: r } : { url: r.url, source: r.source })
    : [];
  const pocList: string[] = Array.isArray(v.poc_urls) ? v.poc_urls : [];

  // Truncate description for "What could happen"
  const whatCouldHappen = desc.length > 220 ? desc.slice(0, 217) + '…' : desc;

  // Who's at risk: from vendors + products (hidden if empty per spec)
  const vendorList: string[] = Array.isArray(v.vendors) && v.vendors.length ? v.vendors : [];
  const productList: string[] = Array.isArray(v.products) && v.products.length ? v.products : [];
  const atRiskParts: string[] = [];
  if (vendorList.length) atRiskParts.push(...vendorList);
  if (productList.length) atRiskParts.push(...productList);
  const atRiskText = atRiskParts.join(', ');
  const showAtRisk = atRiskParts.length > 0;

  const shareUrl = typeof window !== 'undefined' ? window.location.origin + window.location.pathname + `?cve=${encodeURIComponent(row.cve_id)}` : '';

  container.innerHTML = `
    <div class="drawer-header-bar">
      <div class="drawer-header-top">
        <div class="drawer-title-block">
          <span class="drawer-cve-id">// ${escapeHtml(row.cve_id)} — INCIDENT ANALYSIS</span>
          <span class="drawer-title">${escapeHtml(vendor)}: ${escapeHtml(truncate(v.description || row.rationale || 'Security Advisory', 80))}</span>
        </div>
        <div class="drawer-actions">
          <button class="drawer-action-btn" id="btn-share-drawer" title="Copy link">${shareIcon} [ SHARE ]</button>
          <button class="drawer-close-btn" id="btn-close-drawer" aria-label="Close drawer" title="Close">${closeBtnSvg}</button>
        </div>
      </div>

      <!-- STATUS PILLS ROW: status + CVSS + advisory ID + date -->
      <div class="drawer-pills">
        <span class="drawer-pill ${statusPillClass}">[ ${escapeHtml(statusName).toUpperCase()} ]</span>
        ${cvss ? `<span class="drawer-pill pill-neutral">CVSS ${escapeHtml(cvss)}</span>` : ''}
        ${epss ? `<span class="drawer-pill pill-neutral">EPSS ${escapeHtml(epss)}</span>` : ''}
        ${v.is_kev ? `<span class="drawer-pill pill-act">CISA KEV</span>` : ''}
        ${v.poc_public ? `<span class="drawer-pill pill-plan">PoC</span>` : ''}
        <span class="drawer-pill pill-neutral">${escapeHtml(fullDate)}</span>
      </div>
    </div>

    <div class="drawer-body">
      <!-- ATTACK PATH (CVSS-derived) -->
      <div class="drawer-section">
        <div class="drawer-section-label">// 01 ATTACK PATH SCHEMATIC</div>
        <div class="attack-path-container">
          <div class="attack-path-flow">
            <div class="attack-step">
              <div class="step-icon">${globeIcon}</div>
              <div class="step-label">Vector</div>
              <div class="step-val">${escapeHtml(attackVector)}</div>
            </div>
            <div class="attack-step">
              <div class="step-icon">${keyIcon}</div>
              <div class="step-label">Auth Required</div>
              <div class="step-val">${escapeHtml(authRequired)}</div>
            </div>
            <div class="attack-step">
              <div class="step-icon">${gearIcon}</div>
              <div class="step-label">Complexity</div>
              <div class="step-val">${escapeHtml(complexity)}</div>
            </div>
            <div class="attack-step">
              <div class="step-icon">${userIcon}</div>
              <div class="step-label">Interaction</div>
              <div class="step-val">${escapeHtml(userInteraction)}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- SUMMARY -->
      <div class="drawer-section">
        <div class="drawer-section-label">// 02 EXECUTIVE SUMMARY</div>
        <div class="detail-summary-text">${escapeHtml(desc)}</div>
      </div>

      <!-- WHAT THIS MEANS -->
      <div class="drawer-section">
        <div class="drawer-section-label">// 03 IMPACT &amp; AT-RISK ASSETS</div>
        <div class="meaning-list">
          <div class="meaning-item">
            <div>
              <strong>Potential Impact</strong>
              ${escapeHtml(whatCouldHappen)}
            </div>
          </div>
          ${showAtRisk ? `
          <div class="meaning-item">
            <div>
              <strong>Affected Products &amp; Vendors</strong>
              ${escapeHtml(atRiskText)}
            </div>
          </div>
          ` : ''}
        </div>
      </div>

      <!-- REFERENCES -->
      ${refsList.length ? `
      <div class="drawer-section">
        <div class="drawer-section-label">// 04 INTEL REFERENCES</div>
        <ul class="refs-list">
          ${refsList.slice(0, 8).map(r => `
            <li>
              <a href="${escapeHtml(r.url)}" target="_blank" rel="noopener">
                ${r.source ? `<span class="ref-source">${escapeHtml(r.source.toUpperCase())}</span>` : ''}
                <span>${escapeHtml(r.url.length > 70 ? r.url.slice(0, 67) + '…' : r.url)}</span>
              </a>
            </li>
          `).join('')}
        </ul>
      </div>
      ` : ''}

      <!-- POC URLS -->
      ${pocList.length ? `
      <div class="drawer-section">
        <div class="drawer-section-label">// 05 POC EXPLOIT REPOSITORIES</div>
        <ul class="refs-list">
          ${pocList.slice(0, 8).map(u => `
            <li>
              <a href="${escapeHtml(u)}" target="_blank" rel="noopener">
                <span class="ref-source">${linkIcon}</span>
                <span>${escapeHtml(u.length > 70 ? u.slice(0, 67) + '…' : u)}</span>
              </a>
            </li>
          `).join('')}
        </ul>
      </div>
      ` : ''}

      <!-- REMEDIATION -->
      <div class="drawer-section">
        <div class="drawer-section-label">// 06 REMEDIATION DIRECTIVES</div>
        ${v.remediation ? `
          <div class="remediation-text">${escapeHtml(v.remediation)}</div>
        ` : `
          <div class="detail-summary-text" style="color:var(--text-dim);font-style:italic">No official remediation directive indexed. Consult vendor advisories above.</div>
        `}
      </div>

      <div style="font-size:10.5px;color:var(--text-dim);font-family:var(--font-mono);text-align:right;margin-top:auto">
        TELEMETRY_UPDATED: ${escapeHtml(when)}
      </div>
    </div>
  `;

  document.getElementById('btn-close-drawer')?.addEventListener('click', onClose);
  const shareBtn = document.getElementById('btn-share-drawer');
  if (shareBtn) {
    shareBtn.addEventListener('click', async () => {
      try {
        if (navigator.clipboard && shareUrl) {
          await navigator.clipboard.writeText(shareUrl);
          shareBtn.textContent = '✓ COPIED';
          setTimeout(() => { shareBtn.innerHTML = `${shareIcon} [ SHARE ]`; }, 1500);
        }
      } catch {
        // ponytail: clipboard blocked — fail silently; user can copy from URL bar.
      }
    });
  }
}

export function renderVendorSidebar(container: HTMLElement, vendorCounts: Record<string, number>, selectedVendors: Set<string>, onToggle: (vendor: string) => void) {
  const vendors = Object.keys(vendorCounts).sort((a, b) => vendorCounts[b] - vendorCounts[a]);
  if (!vendors.length) {
    container.innerHTML = `<div class="sidebar-loading">NO MONITORED VENDORS</div>`;
    return;
  }

  container.innerHTML = vendors.slice(0, 40).map(v => {
    const isChecked = selectedVendors.has(v);
    const countStr = String(vendorCounts[v]).padStart(2, '0');
    return `
      <div class="vendor-item ${isChecked ? 'is-selected' : ''}" data-vendor="${escapeHtml(v)}">
        <label>
          <input type="checkbox" ${isChecked ? 'checked' : ''} />
          <span class="vendor-name">${escapeHtml(v)}</span>
        </label>
        <span class="vendor-count">${countStr}</span>
      </div>
    `;
  }).join('');

  container.querySelectorAll<HTMLElement>('.vendor-item').forEach(item => {
    const v = item.dataset.vendor;
    const checkbox = item.querySelector('input') as HTMLInputElement;
    if (v && checkbox) {
      checkbox.addEventListener('change', () => onToggle(v));
    }
  });
}
