/**
 * Response shaping for the v3 tools.
 *
 * Field names come from responses recorded against apix.cisco.com
 * (tests/fixtures/cisco). Each shaper returns a concise view by default and
 * a fuller one when response_format = "detailed".
 */

export type ResponseFormat = 'concise' | 'detailed';

/** Normalized paging returned by every list tool */
export interface Paging {
  page: number;
  total_records: number | null;
  last_page: number | null;
  next_page: number | null;
}

/** Drop empty values so concise output stays small */
export function compact<T extends Record<string, any>>(obj: T): Partial<T> {
  const out: Record<string, any> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value) && value.length === 0) continue;
    out[key] = value;
  }
  return out as Partial<T>;
}

const num = (v: unknown): number | null => {
  const n = typeof v === 'string' ? parseInt(v, 10) : typeof v === 'number' ? v : NaN;
  return Number.isFinite(n) ? n : null;
};

function buildPaging(page: unknown, total: unknown, last: unknown): Paging {
  const p = num(page) ?? 1;
  const lastPage = num(last);
  return {
    page: p,
    total_records: num(total),
    last_page: lastPage,
    next_page: lastPage !== null && p < lastPage ? p + 1 : null,
  };
}

/**
 * Cisco APIs use four different pagination envelopes; normalize them all.
 */
export function pagingFrom(body: any, requestedPage = 1, pageSize?: number): Paging {
  const snake = body?.pagination_response_record;
  if (snake) return buildPaging(snake.page_index, snake.total_records, snake.last_index);
  const pascal = body?.PaginationResponseRecord;
  if (pascal) return buildPaging(pascal.PageIndex, pascal.TotalRecords, pascal.LastIndex);
  const camel = body?.paginationResponseRecord ?? body?.APIPagination;
  if (camel) return buildPaging(camel.pageIndex, camel.totalRecords, camel.lastIndex);
  // PSIRT openVuln: { paging: { next, prev, count } }
  const psirt = body?.paging;
  if (psirt) {
    const total = num(psirt.count);
    const last = total !== null && pageSize ? Math.max(1, Math.ceil(total / pageSize)) : null;
    return buildPaging(requestedPage, total, last);
  }
  return { page: requestedPage, total_records: null, last_page: null, next_page: null };
}

/** Bug descriptions are HTML-ish; strip tags and cap length */
function plainText(html: unknown, max: number): string | undefined {
  if (typeof html !== 'string' || !html) return undefined;
  const text = html.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

const releases = (v: unknown): string[] =>
  typeof v === 'string' ? v.split(/\s+/).filter(Boolean) : Array.isArray(v) ? v : [];

/** Keep long lists short in concise output, and say how many were left out */
function capList(items: string[], max: number): string[] {
  return items.length > max ? [...items.slice(0, max), `…+${items.length - max} more`] : items;
}

function capProducts(product: unknown, max: number): string | undefined {
  if (typeof product !== 'string' || !product) return undefined;
  const parts = product.split(',').map(p => p.trim()).filter(Boolean);
  return parts.length > max ? `${parts.slice(0, max).join(', ')} (+${parts.length - max} more)` : parts.join(', ');
}

export function shapeBug(bug: any, format: ResponseFormat) {
  const concise = format === 'concise';
  const base = {
    bug_id: bug.bug_id,
    headline: bug.headline,
    severity: bug.severity,
    status: bug.status,
    product: concise ? capProducts(bug.product, 3) : bug.product,
    last_modified: bug.last_modified_date,
    affected_releases: concise ? capList(releases(bug.known_affected_releases), 8) : releases(bug.known_affected_releases),
    fixed_releases: concise ? capList(releases(bug.known_fixed_releases), 8) : releases(bug.known_fixed_releases),
    url: bug.bug_id ? `https://bst.cloudapps.cisco.com/bugsearch/bug/${bug.bug_id}` : undefined,
  };
  if (format === 'concise') return compact(base);
  return compact({
    ...base,
    description: plainText(bug.description, 4000),
    support_case_count: bug.support_case_count,
    behavior_changed: bug.behavior_changed,
    duplicate_of: bug.duplicate_of,
    created: bug.created_date,
    base_pid: bug.base_pid,
    product_series: bug.product_series,
  });
}

export function shapeAdvisory(adv: any, format: ResponseFormat) {
  const base = {
    advisory_id: adv.advisoryId,
    title: adv.advisoryTitle,
    sir: adv.sir,
    cvss_base_score: adv.cvssBaseScore,
    cves: adv.cves,
    first_published: adv.firstPublished,
    last_updated: adv.lastUpdated,
    first_fixed: adv.firstFixed,
    url: adv.publicationUrl,
  };
  if (format === 'concise') return compact(base);
  return compact({
    ...base,
    status: adv.status,
    version: adv.version,
    bug_ids: adv.bugIDs,
    cwe: adv.cwe,
    affected_releases: adv.iosRelease,
    products: Array.isArray(adv.productNames) ? adv.productNames.slice(0, 50) : undefined,
    summary: plainText(adv.summary, 4000),
    csaf_url: adv.csafUrl,
  });
}

const eoxDate = (d: any): string | undefined => (d && typeof d === 'object' ? d.value : d) || undefined;

export function shapeEox(rec: any, format: ResponseFormat) {
  const announced = !!rec.EOLProductID;
  const base = {
    input: rec.EOXInputValue,
    product_id: rec.EOLProductID || undefined,
    eox_announced: announced,
    description: rec.ProductIDDescription,
    end_of_sale: eoxDate(rec.EndOfSaleDate),
    end_of_sw_maintenance: eoxDate(rec.EndOfSWMaintenanceReleases),
    end_of_security_support: eoxDate(rec.EndOfSecurityVulSupportDate),
    last_date_of_support: eoxDate(rec.LastDateOfSupport),
    migration_product_id: rec.EOXMigrationDetails?.MigrationProductId,
    bulletin_url: rec.LinkToProductBulletinURL,
    error: rec.EOXError?.ErrorDescription,
  };
  if (format === 'concise') return compact(base);
  return compact({
    ...base,
    announcement_date: eoxDate(rec.EOXExternalAnnouncementDate),
    end_of_routine_failure_analysis: eoxDate(rec.EndOfRoutineFailureAnalysisDate),
    end_of_service_contract_renewal: eoxDate(rec.EndOfServiceContractRenewal),
    end_of_service_attach: eoxDate(rec.EndOfSvcAttachDate),
    bulletin_number: rec.ProductBulletinNumber,
    migration_product_name: rec.EOXMigrationDetails?.MigrationProductName,
    migration_strategy: rec.EOXMigrationDetails?.MigrationStrategy,
    migration_info_url: rec.EOXMigrationDetails?.MigrationProductInfoURL,
  });
}

export function shapeProduct(p: any, format: ResponseFormat) {
  const base = {
    product_id: p.product_id ?? p.base_pid,
    serial_number: p.sr_no,
    name: p.product_name,
    series: p.product_series,
    category: p.product_category,
    type: p.product_type,
    orderable_status: p.orderable_status,
    support_page: p.product_support_page,
  };
  if (format === 'concise') return compact(base);
  return compact({
    ...base,
    orderable_pid: p.orderable_pid,
    subcategory: p.product_subcategory,
    release_date: p.release_date,
    form_factor: p.form_factor,
    weight: p.weight,
    dimensions: p.dimensions,
  });
}

export function shapeCoverage(c: any, format: ResponseFormat) {
  const base = {
    serial_number: c.sr_no,
    is_covered: c.is_covered === 'YES' ? true : c.is_covered === 'NO' ? false : c.is_covered,
    coverage_end_date: c.covered_product_line_end_date || c.coverage_end_date,
    warranty_end_date: c.warranty_end_date,
    warranty_type: c.warranty_type,
    service_contract_number: c.service_contract_number,
    service_level: c.service_line_descr,
    orderable_pid: c.orderable_pid_list?.[0]?.orderable_pid,
  };
  if (format === 'concise') return compact(base);
  return compact({
    ...base,
    parent_serial_number: c.parent_sr_no,
    warranty_type_description: c.warranty_type_description,
    base_pids: c.base_pid_list?.map((b: any) => b.base_pid).filter(Boolean),
    contract_site: compact({
      customer: c.contract_site_customer_name,
      address: c.contract_site_address1,
      city: c.contract_site_city,
      state: c.contract_site_state_province,
      country: c.contract_site_country,
    }),
  });
}

export function shapeSoftwareRelease(s: any, format: ResponseFormat) {
  const base = {
    release: s.releaseFormat1,
    suggested: s.isSuggested === 'Y',
    release_date: s.releaseDate,
    lifecycle: s.releaseLifeCycle,
    train: s.releaseTrain,
  };
  if (format === 'concise') return compact(base);
  const seen = new Set<string>();
  return compact({
    ...base,
    display_name: s.relDispName,
    images: (s.images || [])
      .filter((i: any) => i.imageName && !seen.has(i.imageName) && seen.add(i.imageName))
      .map((i: any) => compact({ name: i.imageName, feature_set: i.featureSet, size: i.imageSize })),
  });
}

export function shapeCase(c: any, format: ResponseFormat) {
  const base = {
    case_id: c.case_id,
    title: c.title,
    severity: c.severity,
    status: c.status,
    created: c.creation_date,
    updated: c.updated_date,
    contract_id: c.contract_id,
    serial_number: c.serial_number,
    technology: c.technology_name,
    rmas: c.rmas,
    bugs: c.bugs,
  };
  if (format === 'concise') return compact(base);
  return compact({
    ...base,
    sub_technology: c.sub_technology_name,
    closed: c.close_date,
    owner: c.owner_name,
    owner_email: c.owner_email,
    contact: c.contact_name ?? c.contact_user_id,
    problem_code: c.problem_code_name,
    request_type: c.request_type,
    tracking_number: c.tracking_number,
    notes: Array.isArray(c.notes)
      ? c.notes.slice(0, 20).map((n: any) => compact({ by: n.created_by, at: n.creation_date, note: n.note, detail: plainText(n.note_detail, 1500) }))
      : undefined,
  });
}

export function shapeRma(r: any, format: ResponseFormat) {
  const parts = r.replacementParts?.partsLineDetails ?? [];
  const returns = r.returnLines?.returnParts ?? [];
  const base = {
    rma_number: r.rmaNo,
    status: r.status,
    order_date: r.orderDate,
    case_id: r.caseId,
    service_level: r.serviceLevel,
    replacement_parts: parts.map((p: any) => compact({
      part_number: p.shippedPartNo,
      description: p.partsDescription,
      status: p.partsLineStatus,
      ship_date: p.partsShipDate,
      carrier: p.carrierName ?? p.partsCarrier,
      tracking: p.trackingNumber ?? p.partsTrackingNumber,
    })),
  };
  if (format === 'concise') return compact(base);
  return compact({
    ...base,
    contract_id: r.contractId,
    delivery_type: r.deliveryType,
    failure_class: r.failureClass,
    failure_code: r.failureCode,
    planned_delivery_date: r.plannedDeliveryDate,
    returns: returns.map((p: any) => compact({
      part_number: p.receivedPartNo,
      description: p.returnDescription,
      status: p.returnLineStatus,
      return_by: p.returnToCiscoBy,
    })),
  });
}
