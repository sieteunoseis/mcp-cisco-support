import { BaseApi } from './base-api.js';

/** Cisco EoX API client. Endpoints are called from src/tools (v3 tools). */
export class EoxApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/supporttools/eox/rest/5';
  protected apiName = 'EoX';
}
