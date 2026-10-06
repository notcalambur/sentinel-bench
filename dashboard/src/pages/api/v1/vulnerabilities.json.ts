/**
 * GET /api/v1/vulnerabilities.json
 *
 * Query params (all optional unless flagged):
 *   cve      = CVE-YYYY-NNNN            single-CVE detail (other filters ignored)
 *   domain   = IT | OT                  filter by domain (OT served from advisories)
 *   vendor   = cisco|microsoft|...      filter by vendor (case-insensitive substring)
 *   kev      = true                     only KEV entries
 *   limit    = 1..1000 (default 100)    page size
 *   offset   = 0..n (default 0)         pagination
 *   since    = ISO date                 only updated after this date
 *
 * Returns:
 *   - Single CVE: { cve_id, ..., risk_score, risk_factors, ..., generated_at }
 *   - List:       { data: Vulnerability[], returned, limit, offset, has_more,
 *                   limit_requested, truncated, filters, generated_at }
 *
 * Pagination: `total` is intentionally omitted (free-tier PostgREST times out
 * on count=exact for 4k+ rows). Callers page through `data` until `has_more`
 * is false, incrementing `offset` by `limit` each time.
 */
import type { APIRoute } from 'astro';
import { createClient } from '@supabase/supabase-js';

const CORS = 'https://sentinel-bench.vercel.app';

function jsonHeaders(status = 200): HeadersInit {
  return {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': CORS,
    // ponytail: drop s-maxage — Vercel keys SSR cache by path, ignoring query
    // string. Aggressive s-maxage means ?limit=N is frozen at first-request.
    // max-age=60 still helps browsers; must-revalidate forces edge re-check.
    'Cache-Control': 'public, max-age=60, must-revalidate',
    // ponytail: Vercel's edge cache keys on path, not query string, so
    // different ?limit=N values were colliding on the same cached entry.
    // Vary: * forces per-request caching. Cost: no shared cache, but this
    // endpoint already has per-query results so the hit ratio was 0.
    'Vary': '*',
  };
}

export const GET: APIRoute = async ({ url }) => {
  const sbUrl = import.meta.env.PUBLIC_SUPABASE_URL;
  const sbKey = import.meta.env.PUBLIC_SUPABASE_ANON_KEY;

  if (!sbUrl || !sbKey) {
    return new Response(JSON.stringify({ error: 'server misconfigured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': CORS },
    });
  }

  const sb = createClient(sbUrl, sbKey);

  const params = url.searchParams;
  const cve = (params.get('cve') || '').toUpperCase();

  // Single-CVE detail branch
  if (cve) {
    if (!/^CVE-\d{4}-\d{4,7}$/.test(cve)) {
      return new Response(JSON.stringify({ error: 'invalid_cve_format', cve }), {
        status: 400,
        headers: jsonHeaders(),
      });
    }

    const [{ data: vuln, error: vErr }, { data: score }] = await Promise.all([
      sb.from('vulnerabilities')
        .select('cve_id,cvss_v3_score,cvss_v3_vector,cvss_v4_score,epss_score,epss_percentile,is_kev,kev_date_added,kev_due_date,exploited_in_wild,poc_public,poc_urls,refs,vendors,products,first_seen_at,last_updated_at,description,remediation')
        .eq('cve_id', cve)
        .maybeSingle(),
      sb.from('latest_risk_scores')
        .select('score, factors, rationale, computed_at')
        .eq('cve_id', cve)
        .maybeSingle(),
    ]);

    if (vErr) {
      return new Response(JSON.stringify({ error: vErr.message }), { status: 500, headers: jsonHeaders() });
    }
    if (!vuln) {
      return new Response(JSON.stringify({ error: 'not_found', cve }), { status: 404, headers: jsonHeaders() });
    }

    return new Response(JSON.stringify({
      cve_id: vuln.cve_id,
      cvss_v3_score: vuln.cvss_v3_score,
      cvss_v3_vector: vuln.cvss_v3_vector,
      cvss_v4_score: vuln.cvss_v4_score,
      epss_score: vuln.epss_score,
      epss_percentile: vuln.epss_percentile,
      is_kev: vuln.is_kev,
      kev_date_added: vuln.kev_date_added,
      kev_due_date: vuln.kev_due_date,
      exploited_in_wild: vuln.exploited_in_wild,
      poc_public: vuln.poc_public,
      poc_urls: vuln.poc_urls || [],
      refs: vuln.refs || [],
      vendors: vuln.vendors || [],
      products: vuln.products || [],
      first_seen_at: vuln.first_seen_at,
      last_updated_at: vuln.last_updated_at,
      description: vuln.description,
      remediation: (vuln.remediation && vuln.remediation !== '')
        ? vuln.remediation
        : 'No remediation available',
      risk_score: score?.score ?? null,
      risk_factors: score?.factors ?? null,
      risk_rationale: score?.rationale ?? null,
      computed_at: score?.computed_at ?? null,
      generated_at: new Date().toISOString(),
    }, null, 2), { status: 200, headers: jsonHeaders() });
  }

  const domain = (params.get('domain') || '').toUpperCase();
  const vendor = (params.get('vendor') || '').toLowerCase();
  const kevOnly = params.get('kev') === 'true';
  const requestedLimit = parseInt(params.get('limit') || '100', 10) || 100;
  const limit = Math.min(Math.max(requestedLimit, 1), 1000);
  const offset = Math.max(parseInt(params.get('offset') || '0', 10) || 0, 0);
  const since = params.get('since');

  // OT entries don't live in `vulnerabilities` — they only exist in
  // `advisories` with domain='OT'. Direct callers there instead.
  if (domain === 'OT') {
    const { data: adv, error: advErr } = await sb
      .from('advisories')
      .select('id, source_id, title, summary, url, severity, published_at, vendors, products, cve_ids, domain')
      .eq('domain', 'OT')
      .order('published_at', { ascending: false, nullsFirst: false })
      .range(offset, offset + limit - 1);
    if (advErr) {
      return new Response(JSON.stringify({ error: advErr.message }), {
        status: 500, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': CORS },
      });
    }
    const rows = (adv || []).filter((r: any) => {
      if (vendor) {
        const vs: string[] = r.vendors || [];
        if (!vs.some((v) => String(v).toLowerCase().includes(vendor))) return false;
      }
      // KEV doesn't apply to advisories; only filter when explicitly asked.
      return true;
    });
    return new Response(
      JSON.stringify({
        data: rows,
        returned: rows.length,
        limit,
        limit_requested: requestedLimit,
        truncated: requestedLimit > 1000,
        has_more: rows.length === limit,
        offset,
        filters: { domain, vendor, kev: kevOnly, since },
        generated_at: new Date().toISOString(),
      }, null, 2),
      { status: 200, headers: jsonHeaders() }
    );
  }

  // IT path (or no domain). For IT we still hydrate from `vulnerabilities`;
  // when domain=IT is explicit we keep only CVE rows whose vendors map back
  // to a known IT advisory vendor set. Without that join table we fall back
  // to the same set as no-domain (it's a near-superset today).
  // ponytail: skip count=exact — Supabase does a full sort to honor it and the
  // free tier times out on 4000+ rows. has_more = we got a full page back.
  // Ask for one extra row so has_more is exact without a count query.
  const fetchLimit = limit + 1;
  let q = sb
    .from('latest_risk_scores')
    .select('cve_id, score, factors, rationale, computed_at')
    .order('score', { ascending: false })
    .range(offset, offset + fetchLimit - 1);

  if (since) {
    q = q.gt('computed_at', since);
  }

  const { data: scores, error: scoresErr } = await q;
  if (scoresErr) {
    return new Response(JSON.stringify({ error: scoresErr.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': CORS },
    });
  }

  const allScores = scores || [];
  const hasMoreScores = allScores.length > limit;
  const scoreSlice = hasMoreScores ? allScores.slice(0, limit) : allScores;
  const cveIds = scoreSlice.map((r: any) => r.cve_id).filter(Boolean);
  if (cveIds.length === 0) {
    return new Response(
      JSON.stringify({
        data: [],
        returned: 0,
        limit,
        limit_requested: requestedLimit,
        truncated: requestedLimit > 1000,
        has_more: hasMoreScores,
        offset,
        filters: { domain, vendor, kev: kevOnly, since },
        generated_at: new Date().toISOString(),
      }, null, 2),
      { status: 200, headers: jsonHeaders() }
    );
  }

  // Hydrate with vulnerability details. Push vendor filter to the DB with
  // `cs` (case-sensitive contains) so the row count stays bounded.
  let vQ = sb
    .from('vulnerabilities')
    .select('cve_id,cvss_v3_score,epss_score,is_kev,vendors,products,exploited_in_wild,poc_public,last_updated_at,description,remediation')
    .in('cve_id', cveIds);
  if (vendor) vQ = vQ.contains('vendors', [vendor]);
  const { data: vulns, error: vErr } = await vQ;
  if (vErr) {
    return new Response(JSON.stringify({ error: vErr.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': CORS },
    });
  }

  const vmap = new Map<string, any>((vulns || []).map((v: any) => [v.cve_id, v]));
  // Substring filter after the DB pushdown: vendors may live as
  // "cisco-systems" while callers pass "cisco". Keeps the API permissive
  // without a full table scan on unfiltered pages.
  const vendorSubstr = vendor || null;

  // ponytail: filter+map inline; one pass keeps it cheap.
  let merged = scoreSlice.map((r: any) => {
    const v = vmap.get(r.cve_id);
    if (vendorSubstr) {
      const vs: string[] = v?.vendors || [];
      if (!vs.some((vv: string) => String(vv).toLowerCase().includes(vendorSubstr))) return null;
    }
    return {
      cve_id: r.cve_id,
      score: r.score,
      rationale: r.rationale,
      computed_at: r.computed_at,
      cvss_v3_score: v?.cvss_v3_score ?? null,
      epss_score: v?.epss_score ?? null,
      is_kev: v?.is_kev ?? false,
      vendors: v?.vendors ?? [],
      products: v?.products ?? [],
      exploited_in_wild: v?.exploited_in_wild ?? false,
      poc_public: v?.poc_public ?? false,
      description: v?.description ?? null,
      remediation: (() => { const _r = v?.remediation; return (_r && _r !== '') ? _r : 'No remediation available'; })(),
      last_updated_at: v?.last_updated_at ?? null,
      domain: 'IT',
    };
  }).filter(Boolean) as any[];

  if (kevOnly) merged = merged.filter((r) => r.is_kev);
  // After pushdown + substring, has_more is "scores page was full"; if
  // vendor/KEV trimming removed rows on this page, the next page may still
  // have results — keep has_more=true.
  const hasMoreAfterFilter = hasMoreScores || merged.length === limit;

  return new Response(
    JSON.stringify({
      data: merged,
      returned: merged.length,
      limit,
      limit_requested: requestedLimit,
      truncated: requestedLimit > 1000,
      has_more: hasMoreAfterFilter,
      offset,
      filters: { domain, vendor, kev: kevOnly, since },
      generated_at: new Date().toISOString(),
    }, null, 2),
    { status: 200, headers: jsonHeaders() }
  );
};
