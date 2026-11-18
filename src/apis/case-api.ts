import { BaseApi } from './base-api.js';

/** Cisco Case API client. Endpoints are called from src/tools (v3 tools). */
export class CaseApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/case/v3';
  protected apiName = 'Case';
}
