import {
  ApiResponse,
  BugApiResponse,
  CaseApiResponse,
  EoxApiResponse,
} from "./formatting.js";

/**
 * Convert API responses to TOON format
 * TOON (Text Object-Oriented Notation) provides a more readable and structured output
 */

export async function convertToToonFormat(
  data: ApiResponse,
  apiType: string,
): Promise<string> {
  try {
    const { encode } = await import("@toon-format/toon");
    const toonOutput = encode(data, {
      indent: 2,
    });

    return toonOutput;
  } catch (error) {
    console.error("TOON formatting error:", error);
    return JSON.stringify(data, null, 2);
  }
}

/**
 * Convert bug API response to TOON format
 */
export async function bugResponseToToon(data: BugApiResponse): Promise<string> {
  return convertToToonFormat(data, "bug");
}

/**
 * Convert case API response to TOON format
 */
export async function caseResponseToToon(
  data: CaseApiResponse,
): Promise<string> {
  return convertToToonFormat(data, "case");
}

/**
 * Convert EoX API response to TOON format
 */
export async function eoxResponseToToon(data: EoxApiResponse): Promise<string> {
  return convertToToonFormat(data, "eox");
}

/**
 * Determine if TOON format should be used based on environment variable
 * Defaults to true (TOON enabled) unless explicitly disabled
 */
export function shouldUseToonFormat(): boolean {
  const toonDisabled =
    process.env.DISABLE_TOON_FORMAT?.toLowerCase() === "true";
  return !toonDisabled;
}

/**
 * Get format description for logging/debugging
 */
export function getFormatDescription(): string {
  return shouldUseToonFormat() ? "TOON" : "JSON";
}
