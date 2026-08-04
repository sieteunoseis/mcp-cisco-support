/**
 * GCF vs TOON vs JSON benchmark + TOON corruption proof on Cisco support data.
 * GCF = Graph Compact Format (https://gcformat.com)
 *
 * Uses realistic data shapes from Cisco Support APIs:
 * - Bug API responses (bug_id, headline, status, severity)
 * - Case API responses (case_id, title, status, severity)
 * - EoX API responses (EOLProductID, dates, error records)
 * - Error responses (flat objects with error messages)
 *
 * Usage: node benchmarks/benchmark.mjs
 */

import { encode as toonEncode, decode as toonDecode } from '@toon-format/toon';
import { encodeGeneric, decodeGeneric } from '@blackwell-systems/gcf';

function tokenEstimate(text) {
  return Math.max(1, Math.floor(text.length / 4));
}

// --- Realistic Cisco Support API data generators ---

function generateBugResponse(n) {
  return {
    bugs: Array.from({ length: n }, (_, i) => ({
      bug_id: `CSCvx${String(10000 + i).padStart(5, '0')}`,
      headline: `[${['IOS-XE', 'NX-OS', 'ASA', 'ISE', 'DNAC'][i % 5]}]: ${['Memory leak in process', 'Interface flap on reload', 'SNMP polling timeout', 'Authentication bypass in RADIUS', 'BGP session drops under load'][i % 5]}`,
      status: ['O', 'F', 'T', 'R', 'V'][i % 5],
      severity: `${1 + (i % 6)}`,
      last_modified_date: `2026-0${1 + (i % 9)}-${String(10 + (i % 20)).padStart(2, '0')}T10:00:00Z`,
      product: `Cisco ${['Catalyst 9300', 'Nexus 9000', 'ASA 5500', 'ISE 3.x', 'DNA Center'][i % 5]}`,
      known_affected_releases: [`${15 + (i % 3)}.${i % 10}.${i % 5}`, `${16 + (i % 2)}.${i % 8}.${i % 3}`],
      known_fixed_releases: [`${17 + (i % 2)}.${i % 6}.${i % 4}`],
      description: `Bug found in ${['show running-config', 'interface GigabitEthernet0/1', 'router bgp 65000', 'aaa authentication login'][i % 4]}. Error: ERR[${400 + (i % 10)}]: ${['Not Found', 'Forbidden', 'Timeout', 'Service Unavailable', 'Bad Gateway'][i % 5]}.`,
    })),
    total_results: n,
  };
}

function generateCaseResponse(n) {
  return {
    cases: Array.from({ length: n }, (_, i) => ({
      case_id: `SR ${600000000 + i}`,
      title: `[P${1 + (i % 4)}]: ${['Router crash on reload', 'Switch port security violation', 'VPN tunnel intermittent drops', 'License compliance issue', 'Firmware upgrade failure'][i % 5]}`,
      status: ['Open', 'Customer Pending', 'Engineer Assigned', 'Closed', 'Resolved'][i % 5],
      severity: `${1 + (i % 4)}`,
      created_date: `2026-0${1 + (i % 9)}-${String(1 + (i % 28)).padStart(2, '0')}`,
      last_modified_date: `2026-06-${String(1 + (i % 18)).padStart(2, '0')}`,
      contract_id: `CON-SNT-${['C93002', 'N9K96', 'ASA55', 'ISE30', 'DNAC2'][i % 5]}${i}`,
      serial_number: `FCW${2100 + i}${String.fromCharCode(65 + (i % 26))}${String.fromCharCode(65 + ((i + 7) % 26))}${String.fromCharCode(65 + ((i + 13) % 26))}`,
    })),
    total_results: n,
  };
}

function generateEoxResponse(n) {
  return {
    EOXRecord: Array.from({ length: n }, (_, i) => ({
      EOLProductID: `WS-C${3750 + (i % 50)}X-${24 + (i % 4) * 12}${['T', 'P', 'S'][i % 3]}-${['S', 'L', 'E'][i % 3]}`,
      ProductIDDescription: `Cisco Catalyst ${3750 + (i % 50)}X ${24 + (i % 4) * 12}-Port ${['10/100/1000', 'PoE+', 'SFP+'][i % 3]}`,
      ProductBulletinNumber: `EOL${14000 + i}`,
      LinkToProductBulletinURL: `https://www.cisco.com/c/en/us/products/collateral/switches/eol${14000 + i}.html`,
      EOXExternalAnnouncementDate: { dateFormat: 'YYYY-MM-DD', value: `202${3 + (i % 3)}-0${1 + (i % 9)}-01` },
      EndOfSaleDate: { dateFormat: 'YYYY-MM-DD', value: `202${4 + (i % 3)}-0${1 + (i % 9)}-01` },
      EndOfSWMaintenanceReleases: { dateFormat: 'YYYY-MM-DD', value: `202${5 + (i % 3)}-0${1 + (i % 9)}-01` },
      LastDateOfSupport: { dateFormat: 'YYYY-MM-DD', value: `202${8 + (i % 3)}-0${1 + (i % 9)}-01` },
      EOXError: i % 7 === 0 ? {
        ErrorID: `ERR[${400 + (i % 5)}]`,
        ErrorDescription: `[ProductID]: ${['Not found in database', 'Invalid format', 'Deprecated endpoint'][i % 3]}`,
      } : null,
      EOXInputType: 'ShowEoXByPids',
      EOXInputValue: `WS-C${3750 + (i % 50)}X`,
    })),
    PaginationResponseRecord: {
      PageIndex: 1,
      LastIndex: Math.ceil(n / 20),
      TotalRecords: n,
      PageRecords: Math.min(n, 20),
    },
  };
}

function generateErrorResponses(n) {
  return Array.from({ length: n }, (_, i) => ({
    error: `ERR[${400 + (i % 5)}]: ${['Not Found', 'Unauthorized', 'Forbidden', 'Rate Limited', 'Internal Server Error'][i % 5]}`,
    message: `API request failed for endpoint /api/v2/${['bugs', 'cases', 'eox', 'product'][i % 4]}`,
    timestamp: `2026-06-18T${String(10 + (i % 12)).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}:00Z`,
    request_id: `req-${i}-${Date.now()}`,
  }));
}

// =====================================================================
// PART 1: TOKEN BENCHMARK
// =====================================================================

console.log('='.repeat(80));
console.log('PART 1: Token Benchmark — GCF vs TOON vs JSON on Cisco Support Data');
console.log('='.repeat(80));
console.log();

const datasets = [
  { name: 'Bug API (50)', data: generateBugResponse(50) },
  { name: 'Case API (50)', data: generateCaseResponse(50) },
  { name: 'EoX API (50)', data: generateEoxResponse(50) },
  { name: 'Bug API (200)', data: generateBugResponse(200) },
  { name: 'Case API (200)', data: generateCaseResponse(200) },
  { name: 'EoX API (200)', data: generateEoxResponse(200) },
];

console.log(
  `${'Dataset'.padEnd(20)}  ${'JSON'.padStart(8)}  ${'TOON'.padStart(8)}  ${'GCF'.padStart(8)}  ${'TOON%'.padStart(7)}  ${'GCF%'.padStart(7)}  ${'GCF vs TOON'.padStart(12)}`
);
console.log('-'.repeat(80));

let totalJson = 0, totalToon = 0, totalGcf = 0;

for (const { name, data } of datasets) {
  const jsonStr = JSON.stringify(data);
  const toonStr = toonEncode(data);
  const gcfStr = encodeGeneric(data);

  const jsonTok = tokenEstimate(jsonStr);
  const toonTok = tokenEstimate(toonStr);
  const gcfTok = tokenEstimate(gcfStr);

  totalJson += jsonTok;
  totalToon += toonTok;
  totalGcf += gcfTok;

  const toonPct = ((1 - toonTok / jsonTok) * 100).toFixed(1);
  const gcfPct = ((1 - gcfTok / jsonTok) * 100).toFixed(1);
  const gcfVsToon = ((1 - gcfTok / toonTok) * 100).toFixed(1);

  console.log(
    `${name.padEnd(20)}  ${String(jsonTok).padStart(8)}  ${String(toonTok).padStart(8)}  ${String(gcfTok).padStart(8)}  ${(toonPct + '%').padStart(7)}  ${(gcfPct + '%').padStart(7)}  ${((gcfVsToon > 0 ? '+' : '') + gcfVsToon + '%').padStart(12)}`
  );
}

console.log('-'.repeat(80));
const toonTotalPct = ((1 - totalToon / totalJson) * 100).toFixed(1);
const gcfTotalPct = ((1 - totalGcf / totalJson) * 100).toFixed(1);
const gcfVsToonTotal = ((1 - totalGcf / totalToon) * 100).toFixed(1);
console.log(
  `${'TOTAL'.padEnd(20)}  ${String(totalJson).padStart(8)}  ${String(totalToon).padStart(8)}  ${String(totalGcf).padStart(8)}  ${(toonTotalPct + '%').padStart(7)}  ${(gcfTotalPct + '%').padStart(7)}  ${((gcfVsToonTotal > 0 ? '+' : '') + gcfVsToonTotal + '%').padStart(12)}`
);

// =====================================================================
// PART 2: TOON CORRUPTION PROOF
// =====================================================================

console.log();
console.log('='.repeat(80));
console.log('PART 2: TOON Corruption Proof — Round-Trip on Individual Records');
console.log('='.repeat(80));
console.log();

// Test individual flat objects (error responses, single bug records, EoX errors)
const testRecords = [
  ...generateErrorResponses(10),
  ...generateBugResponse(10).bugs,
  ...generateEoxResponse(10).EOXRecord.filter(r => r.EOXError),
];

let toonCorruptions = 0;
let toonErrors = 0;
let gcfCorruptions = 0;
let gcfErrors = 0;

for (const record of testRecords) {
  try {
    const encoded = toonEncode(record);
    const decoded = toonDecode(encoded);
    if (JSON.stringify(decoded) !== JSON.stringify(record)) {
      toonCorruptions++;
      if (toonCorruptions <= 3) {
        console.log(`TOON SILENT CORRUPTION:`);
        console.log(`  Original: ${JSON.stringify(record).slice(0, 120)}...`);
        console.log(`  Decoded:  ${JSON.stringify(decoded).slice(0, 120)}...`);
        console.log();
      }
    }
  } catch (e) {
    toonErrors++;
    if (toonErrors <= 5) {
      console.log(`TOON DECODE ERROR: ${e.message}`);
      console.log(`  Record: ${JSON.stringify(record).slice(0, 120)}...`);
      console.log();
    }
  }

  try {
    const encoded = encodeGeneric(record);
    const decoded = decodeGeneric(encoded);
    if (JSON.stringify(decoded) !== JSON.stringify(record)) {
      gcfCorruptions++;
    }
  } catch (e) {
    gcfErrors++;
  }
}

console.log('='.repeat(80));
console.log('SUMMARY');
console.log('='.repeat(80));
console.log();
console.log(`Records tested: ${testRecords.length}`);
console.log(`TOON corruptions: ${toonCorruptions} | TOON errors: ${toonErrors} | Total failures: ${toonCorruptions + toonErrors}/${testRecords.length}`);
console.log(`GCF corruptions:  ${gcfCorruptions} | GCF errors:  ${gcfErrors} | Total failures: ${gcfCorruptions + gcfErrors}/${testRecords.length}`);
