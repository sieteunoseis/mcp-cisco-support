import { BaseApi } from './base-api.js';

/** Cisco Product API client. Endpoints are called from src/tools (v3 tools). */
export class ProductApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/product/v1/information';
  protected apiName = 'Product';
}
