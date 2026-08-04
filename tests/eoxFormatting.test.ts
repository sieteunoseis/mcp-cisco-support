import { formatEoxResults, EoxApiResponse } from '../src/utils/formatting';

/**
 * Regression tests for EoX response formatting.
 *
 * These cover the mapping layer between the Cisco EoX API and the text the
 * MCP client renders. They run offline against fixture responses shaped after
 * the documented EoX v5 payload, so no Cisco credentials are required.
 */

const dateField = (value: string) => ({ value, dateFormat: 'YYYY-MM-DD' });

const eoxRecord = (overrides: Record<string, any> = {}) => ({
  EOLProductID: 'WIC-1T=',
  ProductIDDescription: 'WAN Interface Card',
  EndOfSaleDate: dateField('2009-12-28'),
  LastDateOfSupport: dateField('2014-12-27'),
  EOXInputType: 'ShowEOXByPids',
  EOXInputValue: 'WIC-1T=',
  ...overrides,
});

describe('formatEoxResults', () => {
  it('renders a populated EoX record', () => {
    const data: EoxApiResponse = { EOXRecord: [eoxRecord()] };
    const out = formatEoxResults(data);

    expect(out).toContain('Cisco End-of-Life (EoX) Results');
    expect(out).toContain('WIC-1T=');
    expect(out).toContain('2009-12-28');
  });

  it('renders an empty result set as readable text, not raw JSON', () => {
    // Cisco returns an empty EOXRecord array when a valid product simply has
    // no EoX data. That is a normal answer, not a malformed response, so the
    // user should get a sentence rather than a dumped JSON blob.
    const data: EoxApiResponse = {
      EOXRecord: [],
      PaginationResponseRecord: {
        PageIndex: 1,
        LastIndex: 1,
        TotalRecords: 0,
        PageRecords: 0,
      },
    };

    const out = formatEoxResults(data);

    expect(out).not.toContain('"PaginationResponseRecord"');
    expect(out).toMatch(/no .*end-of-life|no eox|not found/i);
  });

  it('reports an EoX lookup error for an unknown product', () => {
    const data: EoxApiResponse = {
      EOXRecord: [
        {
          EOXError: {
            ErrorID: 'SSA_ERR_026',
            ErrorDescription: 'EOX information does not exist for the following product ID(s)',
            ErrorDataType: 'PRODUCT_ID',
            ErrorDataValue: 'BOGUS-PID',
          },
          EOXInputType: 'ShowEOXByPids',
          EOXInputValue: 'BOGUS-PID',
        },
      ],
    };

    const out = formatEoxResults(data);
    expect(out).toContain('SSA_ERR_026');
    expect(out).toContain('BOGUS-PID');
  });

  it('preserves a numeric zero returned by the vendor', () => {
    // `extractValue` guarded with a plain falsy check, so a numeric 0 was
    // indistinguishable from an absent field and silently vanished from the
    // report. A migration flag or count of 0 is real data.
    const data: EoxApiResponse = {
      EOXRecord: [
        eoxRecord({
          ProductIDDescription: 0,
          MigrationProductId: { value: 0 },
        }),
      ],
    };

    const out = formatEoxResults(data);
    expect(out).toContain('**Product Description:** 0');
  });

  it('still omits genuinely absent and blank fields', () => {
    const data: EoxApiResponse = {
      EOXRecord: [
        eoxRecord({
          ProductIDDescription: null,
          EndOfSWMaintenanceReleases: dateField(''),
        }),
      ],
    };

    const out = formatEoxResults(data);
    expect(out).not.toContain('**Product Description:**');
    expect(out).not.toContain('**End of SW Maintenance:**');
  });

  it('keeps Cisco acronyms intact in generated field labels', () => {
    // Splitting on every capital rendered "EOXInputType" as "E O X Input Type".
    const data: EoxApiResponse = { EOXRecord: [eoxRecord()] };
    const out = formatEoxResults(data);

    expect(out).toContain('EOX Input Type');
    expect(out).not.toContain('E O X');
  });

  it('renders pagination details when present', () => {
    const data: EoxApiResponse = {
      EOXRecord: [eoxRecord()],
      PaginationResponseRecord: {
        PageIndex: 2,
        LastIndex: 5,
        TotalRecords: 47,
        PageRecords: 10,
      },
    };

    const out = formatEoxResults(data);
    expect(out).toContain('2');
    expect(out).toContain('47');
  });
});
