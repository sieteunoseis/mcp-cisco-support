import { BaseApi } from './base-api.js';

/** Cisco Software API client. Endpoints are called from src/tools (v3 tools). */
export class SoftwareApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/software/suggestion/v2';
  protected apiName = 'Software';
}
