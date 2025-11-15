import { encode } from '@toon-format/toon';
import { ApiResponse, BugApiResponse, CaseApiResponse, EoxApiResponse } from './formatting.js';

/**
 * Convert API responses to TOON format
 * TOON (Text Object-Oriented Notation) provides a more readable and structured output
 */

export function convertToToonFormat(data: ApiResponse, apiType: string): string {
  try {
    // Use the TOON library to encode the data into TOON format
    const toonOutput = encode(data, {
      indent: 2,  // Use 2-space indentation for readability
    });

    return toonOutput;
  } catch (error) {
    // Fallback to JSON if TOON formatting fails
    console.error('TOON formatting error:', error);
    return JSON.stringify(data, null, 2);
  }
}

/**
 * Convert bug API response to TOON format
 */
export function bugResponseToToon(data: BugApiResponse): string {
  return convertToToonFormat(data, 'bug');
}

/**
 * Convert case API response to TOON format
 */
export function caseResponseToToon(data: CaseApiResponse): string {
  return convertToToonFormat(data, 'case');
}

/**
 * Convert EoX API response to TOON format
 */
export function eoxResponseToToon(data: EoxApiResponse): string {
  return convertToToonFormat(data, 'eox');
}

/**
 * Determine if TOON format should be used based on environment variable
 * Defaults to true (TOON enabled) unless explicitly disabled
 */
export function shouldUseToonFormat(): boolean {
  const toonDisabled = process.env.DISABLE_TOON_FORMAT?.toLowerCase() === 'true';
  return !toonDisabled;
}

/**
 * Get format description for logging/debugging
 */
export function getFormatDescription(): string {
  return shouldUseToonFormat() ? 'TOON' : 'JSON';
}
