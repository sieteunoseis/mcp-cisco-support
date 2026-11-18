import { BaseApi } from './base-api.js';

/** Cisco RMA API client. Endpoints are called from src/tools (v3 tools). */
export class RmaApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/return/v1.0';
  protected apiName = 'RMA';
}
