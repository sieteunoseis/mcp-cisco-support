# Tool examples (v3)

Every tool is read-only. Results are concise unless `response_format` is `"detailed"`. List results include `paging` (`total_records`, `next_page`), and empty results include a `hint`.

## Bugs (`SUPPORT_API=bug`)

```jsonc
// Bug details (up to 5 IDs); unknown IDs are listed in not_found
bug_get { "bug_ids": "CSCwh87343" }

// Keyword search across several severities in one call
bug_search { "keyword": "memory leak", "severity": ["1", "2"], "status": "O" }

// Bugs affecting a release on a product (leading zeros are removed: 17.09.04 -> 17.9.4)
bug_search { "product_id": "C9300-48P", "releases": "17.15.4b", "status": "O" }

// Bugs fixed in a release, by series or exact product name
bug_search { "product_series": "Cisco Catalyst 9200 Series Switches", "releases": "17.9.5", "release_match": "fixed" }
bug_search { "product_name": "Cisco Unified Communications Manager (CallManager)", "releases": "12.5(1)" }

// Upgrade assessment; without target_version uses Cisco's suggested release
assess_upgrade { "product_id": "C9300-48P", "current_version": "17.15.4b", "os_type": "iosxe" }
```

## Security advisories (`psirt`)

```jsonc
psirt_get { "cve": "CVE-2023-20198" }
psirt_get { "advisory_id": "cisco-sa-iosxe-webui-privesc-j22SaA4z" }

// Is this release vulnerable? (advisories affecting it, with first fixed releases)
psirt_search { "os_type": "iosxe", "version": "17.15.4b" }

psirt_search { "severity": "critical", "page_size": 5 }
psirt_search { "product": "Cisco Unified Communications Manager" }
psirt_search { "first_published_from": "2026-10-01", "first_published_to": "2026-10-31" }
```

## Lifecycle, devices, products, software

```jsonc
eox_get { "product_ids": "VG224,C9300-48P" }
eox_get { "software_releases": "15.4(3)M,IOS" }
eox_get { "start_date": "2026-01-01", "end_date": "2026-01-31", "page_size": 20 }

// Coverage + product + EoX per serial (needs serial, product and/or eox enabled)
device_lookup { "serial_numbers": "FJC29161RHS,FTX1917AJJU" }

product_get { "product_ids": "C9300-48P,ISR4431/K9", "include_mdf": true }

software_get { "product_ids": "C9300-48P" }                       // Cisco suggested releases
software_get { "product_ids": "C9300-48P", "view": "releases" }   // latest releases
software_get { "product_ids": "ISR4431/K9", "view": "compatible", "current_release": "17.9.4" }
```

## Cases and RMAs (`case`, `rma`)

```jsonc
case_get { "case_ids": "700000001", "response_format": "detailed" }   // adds notes, owner, contact
case_search { "contract_ids": "200000001", "status_flag": "O" }
rma_get { "rma_number": "800000001" }
rma_get { "user_id": "someone@example.com", "from_date": "2026-09-01", "to_date": "2026-11-18" }
```
