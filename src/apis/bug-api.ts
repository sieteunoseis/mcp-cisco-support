import { BaseApi } from './base-api.js';

/** Cisco Bug API client. Endpoints are called from src/tools (v3 tools). */
export class BugApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/bug/v2.0';
  protected apiName = 'Bug';
}
