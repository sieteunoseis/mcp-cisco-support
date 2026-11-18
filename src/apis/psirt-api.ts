import { BaseApi } from './base-api.js';

/** Cisco PSIRT API client. Endpoints are called from src/tools (v3 tools). */
export class PsirtApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/security/advisories/v2';
  protected apiName = 'PSIRT';
}
