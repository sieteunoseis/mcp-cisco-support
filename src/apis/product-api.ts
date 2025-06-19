import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BaseApi } from './base-api.js';
import { ToolArgs } from '../utils/validation.js';
import { ApiResponse } from '../utils/formatting.js';

export class ProductApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/product/v1/information';
  protected apiName = 'Product';

  getTools(): Tool[] {
    return [
      {
        name: 'get_product_info_by_serial_numbers',
        title: 'Get Product Info by Serial Numbers',
        description: 'Get detailed product information for up to 5 device serial numbers. Returns specifications, orderable PIDs, and product details.',
        inputSchema: {
          type: 'object',
          properties: {
            serial_numbers: {
              type: 'string',
              description: 'Comma-separated list of device serial numbers (up to 5). Example: FOC1710W3DY,SMG1149NKBS'
            },
            page_index: {
              type: 'integer',
              default: 1,
              minimum: 1,
              description: 'Page number for pagination (starts at 1)'
            }
          },
          required: ['serial_numbers']
        }
      },
      {
        name: 'get_product_info_by_product_ids',
        title: 'Get Product Info by Product IDs',
        description: 'Get detailed product information for up to 5 product identifiers (PIDs). Returns specifications, descriptions, and technical details.',
        inputSchema: {
          type: 'object',
          properties: {
            product_ids: {
              type: 'string',
              description: 'Comma-separated list of product identifiers/PIDs (up to 5). Example: BLKR-SVB-100U-1Y-U,WS-C6509-E'
            },
            page_index: {
              type: 'integer',
              default: 1,
              minimum: 1,
              description: 'Page number for pagination (starts at 1)'
            }
          },
          required: ['product_ids']
        }
      },
      {
        name: 'get_product_mdf_info_by_product_ids',
        title: 'Get Product MDF Info by Product IDs',
        description: 'Get Manufacturing Data Format (MDF) information for up to 5 product identifiers. Returns detailed manufacturing specifications and data format information. Note: Only hardware products are supported.',
        inputSchema: {
          type: 'object',
          properties: {
            product_ids: {
              type: 'string',
              description: 'Comma-separated list of product identifiers/PIDs (up to 5). Example: ASA5505-50-BUN-K9,WS-C6509-E. Note: Only hardware products supported.'
            },
            page_index: {
              type: 'integer',
              default: 1,
              minimum: 1,
              description: 'Page number for pagination (starts at 1). Maximum 500 records per page.'
            }
          },
          required: ['product_ids']
        }
      }
    ];
  }

  async executeTool(name: string, args: ToolArgs): Promise<ApiResponse> {
    const { tool, processedArgs } = this.validateTool(name, args);
    
    switch (name) {
      case 'get_product_info_by_serial_numbers':
        return await this.getProductInfoBySerialNumbers(processedArgs);
      case 'get_product_info_by_product_ids':
        return await this.getProductInfoByProductIds(processedArgs);
      case 'get_product_mdf_info_by_product_ids':
        return await this.getProductMdfInfoByProductIds(processedArgs);
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  private async getProductInfoBySerialNumbers(args: ToolArgs): Promise<ApiResponse> {
    // Validate serial numbers count
    const serialNumbers = args.serial_numbers.split(',').map((s: string) => s.trim());
    if (serialNumbers.length > 5) {
      return {
        error: 'Too Many Serial Numbers',
        message: 'The Product Information API supports a maximum of 5 serial numbers per request. Please split your request into multiple calls.',
        data: null
      };
    }

    const params: Record<string, any> = {};
    if (args.page_index) params.page_index = args.page_index;

    const response = await this.makeApiCall(`/serial_numbers/${args.serial_numbers}`, params);
    
    return this.formatProductInfoResponse(response, `Product Information for Serial Numbers: ${args.serial_numbers}`);
  }

  private async getProductInfoByProductIds(args: ToolArgs): Promise<ApiResponse> {
    // Validate product IDs count
    const productIds = args.product_ids.split(',').map((s: string) => s.trim());
    if (productIds.length > 5) {
      return {
        error: 'Too Many Product IDs',
        message: 'The Product Information API supports a maximum of 5 product IDs per request. Please split your request into multiple calls.',
        data: null
      };
    }

    const params: Record<string, any> = {};
    if (args.page_index) params.page_index = args.page_index;

    const response = await this.makeApiCall(`/product_ids/${args.product_ids}`, params);
    
    return this.formatProductInfoResponse(response, `Product Information for Product IDs: ${args.product_ids}`);
  }

  private async getProductMdfInfoByProductIds(args: ToolArgs): Promise<ApiResponse> {
    // Validate product IDs count
    const productIds = args.product_ids.split(',').map((s: string) => s.trim());
    if (productIds.length > 5) {
      return {
        error: 'Too Many Product IDs',
        message: 'The Product MDF API supports a maximum of 5 product IDs per request. Please split your request into multiple calls.',
        data: null
      };
    }

    const params: Record<string, any> = {};
    if (args.page_index) params.page_index = args.page_index;

    const response = await this.makeApiCall(`/product_ids_mdf/${args.product_ids}`, params);
    
    return this.formatProductMdfResponse(response, `Product MDF Information for Product IDs: ${args.product_ids}`);
  }

  private formatProductInfoResponse(data: any, title: string): ApiResponse {
    if (!data || (!data.products && !data.product_list)) {
      return {
        error: 'No Data Found',
        message: 'No product information found for the specified serial numbers or product IDs.',
        data: null
      };
    }

    // Handle different response formats from the API
    const products = data.products || data.product_list || [];
    const formattedProducts = products.map((product: any) => this.formatProduct(product));

    return {
      data: {
        title,
        count: products.length,
        total_results: data.total_results || products.length,
        products: formattedProducts,
        pagination: data.pagination_info || null
      }
    };
  }

  private formatProduct(product: any): any {
    return {
      // Basic product identification
      product_id: product.product_id || product.pid || product.base_pid,
      serial_number: product.serial_number || product.sn,
      product_name: product.product_name || product.name || product.description,
      product_type: product.product_type || product.type,
      
      // Product series and family information
      product_series: product.product_series || product.series,
      product_family: product.product_family || product.family,
      
      // Technical specifications
      dimensions: product.dimensions || null,
      weight: product.weight || null,
      power_consumption: product.power_consumption || product.power || null,
      operating_temperature: product.operating_temperature || product.temp_range || null,
      
      // Orderable information
      orderable_pid: product.orderable_pid || product.order_pid,
      list_price: product.list_price || product.price || null,
      currency: product.currency || null,
      
      // Status and lifecycle
      product_status: product.product_status || product.status,
      lifecycle_state: product.lifecycle_state || product.lifecycle,
      end_of_life_date: product.end_of_life_date || product.eol_date || null,
      end_of_sale_date: product.end_of_sale_date || product.eos_date || null,
      
      // Documentation and support
      datasheet_url: product.datasheet_url || product.datasheet || null,
      support_page_url: product.support_page_url || product.support_url || null,
      
      // Additional metadata
      last_updated: product.last_updated || product.updated_date || null,
      cisco_url: this.generateCiscoProductUrl(product.product_id || product.pid || product.base_pid)
    };
  }

  private formatProductMdfResponse(data: any, title: string): ApiResponse {
    if (!data || (!data.products && !data.product_list && !data.mdf_data)) {
      return {
        error: 'No MDF Data Found',
        message: 'No Manufacturing Data Format information found for the specified product IDs.',
        data: null
      };
    }

    // Handle different response formats from the MDF API
    const products = data.products || data.product_list || data.mdf_data || [];
    const formattedProducts = products.map((product: any) => this.formatMdfProduct(product));

    return {
      data: {
        title,
        count: products.length,
        total_results: data.total_results || products.length,
        mdf_products: formattedProducts,
        pagination: data.pagination_info || null
      }
    };
  }

  private formatMdfProduct(product: any): any {
    return {
      // Basic product identification
      product_id: product.product_id || product.pid || product.base_pid,
      product_name: product.product_name || product.name || product.description,
      
      // MDF-specific manufacturing data
      manufacturing_data: {
        part_number: product.part_number || product.pn,
        manufacturing_date: product.manufacturing_date || product.mfg_date,
        manufacturing_location: product.manufacturing_location || product.mfg_location,
        hardware_revision: product.hardware_revision || product.hw_rev,
        firmware_version: product.firmware_version || product.fw_version,
        serial_number_format: product.serial_number_format || product.sn_format,
        barcode_format: product.barcode_format || product.bc_format
      },
      
      // Technical specifications
      physical_specifications: {
        dimensions: product.dimensions || null,
        weight: product.weight || null,
        operating_temperature: product.operating_temperature || product.temp_range || null,
        power_requirements: product.power_requirements || product.power || null
      },
      
      // Compliance and certifications
      compliance: {
        regulatory_compliance: product.regulatory_compliance || product.compliance || null,
        certifications: product.certifications || null,
        safety_standards: product.safety_standards || product.safety || null
      },
      
      // Additional MDF metadata
      data_format_version: product.data_format_version || product.mdf_version,
      last_updated: product.last_updated || product.updated_date || null,
      cisco_url: this.generateCiscoProductUrl(product.product_id || product.pid || product.base_pid)
    };
  }

  private generateCiscoProductUrl(productId: string): string | null {
    if (!productId) return null;
    // Generate URL to Cisco's modern search page
    return `https://search.cisco.com/search?query=${encodeURIComponent(productId)}`;
  }

  // Override getResultCount for Product API responses
  protected getResultCount(data: ApiResponse): number {
    if ('products' in data && Array.isArray(data.products)) {
      return data.products.length;
    }
    if ('product_list' in data && Array.isArray(data.product_list)) {
      return data.product_list.length;
    }
    if ('mdf_products' in data && Array.isArray(data.mdf_products)) {
      return data.mdf_products.length;
    }
    if ('mdf_data' in data && Array.isArray(data.mdf_data)) {
      return data.mdf_data.length;
    }
    return 0;
  }
}