import { BaseApi } from './base-api.js';

/** Cisco Serial API client. Endpoints are called from src/tools (v3 tools). */
export class SerialApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/sn2info/v2';
  protected apiName = 'Serial';
}
