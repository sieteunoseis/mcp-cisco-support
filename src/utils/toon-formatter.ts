import {
  ApiResponse,
  BugApiResponse,
  CaseApiResponse,
  EoxApiResponse,
} from "./formatting.js";
import { encodeGeneric } from "@blackwell-systems/gcf";

/**
 * Convert API responses to GCF (Graph Compact Format)
 * GCF provides 28.5% fewer tokens than JSON on Cisco API data,
 * with 90.7% LLM comprehension accuracy (vs 53.6% JSON).
 */

export async function convertToToonFormat(
  data: ApiResponse,
  apiType: string,
): Promise<string> {
  try {
    return encodeGeneric(data);
  } catch (error) {
    console.error("GCF formatting error:", error);
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
 * Determine if compact format should be used based on environment variable
 * Defaults to true (GCF enabled) unless explicitly disabled
 */
export function shouldUseToonFormat(): boolean {
  const disabled =
    process.env.DISABLE_TOON_FORMAT?.toLowerCase() === "true";
  return !disabled;
}

/**
 * Get format description for logging/debugging
 */
export function getFormatDescription(): string {
  return shouldUseToonFormat() ? "GCF" : "JSON";
}
