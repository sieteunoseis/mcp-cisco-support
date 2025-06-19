import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BaseApi } from './base-api.js';
import { ToolArgs } from '../utils/validation.js';
import { ApiResponse } from '../utils/formatting.js';

export class SoftwareApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/software/suggestion/v2';
  protected apiName = 'Software';

  getTools(): Tool[] {
    return [
      {
        name: 'get_software_suggestions_by_product_ids',
        title: 'Get Software Suggestions by Product IDs',
        description: 'Get software suggestions including recommended releases and images for specified product IDs. Returns detailed software recommendations for planning upgrades and deployments.',
        inputSchema: {
          type: 'object',
          properties: {
            product_ids: {
              type: 'string',
              description: 'Comma-separated list of product identifiers/PIDs. Example: C9300-48P-A,C9300-24P-A'
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
        name: 'get_software_releases_by_product_ids',
        title: 'Get Software Releases by Product IDs',
        description: 'Get suggested software releases (without images) for specified product IDs. Focuses on release versions and recommendations without image details.',
        inputSchema: {
          type: 'object',
          properties: {
            product_ids: {
              type: 'string',
              description: 'Comma-separated list of product identifiers/PIDs. Example: C9300-48P-A,C9300-24P-A'
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
        name: 'get_compatible_software_by_product_id',
        title: 'Get Compatible Software by Product ID',
        description: 'Get compatible and suggested software releases for a specific product ID. Useful for finding upgrade paths from current software versions.',
        inputSchema: {
          type: 'object',
          properties: {
            product_id: {
              type: 'string',
              description: 'Single product identifier/PID. Example: C9300-48P-A'
            },
            current_image: {
              type: 'string',
              description: 'Current software image name (optional). Example: cat9k_iosxe.17.09.04a.SPA.bin'
            },
            current_release: {
              type: 'string',
              description: 'Current software release (optional). Example: 17.09.04a'
            },
            page_index: {
              type: 'integer',
              default: 1,
              minimum: 1,
              description: 'Page number for pagination (starts at 1)'
            }
          },
          required: ['product_id']
        }
      },
      {
        name: 'get_software_suggestions_by_mdf_ids',
        title: 'Get Software Suggestions by MDF IDs',
        description: 'Get software suggestions including recommended releases and images for specified MDF IDs. MDF IDs are Manufacturing Data Format identifiers.',
        inputSchema: {
          type: 'object',
          properties: {
            mdf_ids: {
              type: 'string',
              description: 'Comma-separated list of MDF identifiers. Example: 286313994,286313995'
            },
            page_index: {
              type: 'integer',
              default: 1,
              minimum: 1,
              description: 'Page number for pagination (starts at 1)'
            }
          },
          required: ['mdf_ids']
        }
      },
      {
        name: 'get_software_releases_by_mdf_ids',
        title: 'Get Software Releases by MDF IDs',
        description: 'Get suggested software releases (without images) for specified MDF IDs. Focuses on release versions and recommendations without image details.',
        inputSchema: {
          type: 'object',
          properties: {
            mdf_ids: {
              type: 'string',
              description: 'Comma-separated list of MDF identifiers. Example: 286313994,286313995'
            },
            page_index: {
              type: 'integer',
              default: 1,
              minimum: 1,
              description: 'Page number for pagination (starts at 1)'
            }
          },
          required: ['mdf_ids']
        }
      },
      {
        name: 'get_compatible_software_by_mdf_id',
        title: 'Get Compatible Software by MDF ID',
        description: 'Get compatible and suggested software releases for a specific MDF ID. Useful for finding upgrade paths from current software versions.',
        inputSchema: {
          type: 'object',
          properties: {
            mdf_id: {
              type: 'string',
              description: 'Single MDF identifier. Example: 286313994'
            },
            current_image: {
              type: 'string',
              description: 'Current software image name (optional). Example: cat9k_iosxe.17.09.04a.SPA.bin'
            },
            current_release: {
              type: 'string',
              description: 'Current software release (optional). Example: 17.09.04a'
            },
            page_index: {
              type: 'integer',
              default: 1,
              minimum: 1,
              description: 'Page number for pagination (starts at 1)'
            }
          },
          required: ['mdf_id']
        }
      }
    ];
  }

  async executeTool(name: string, args: ToolArgs): Promise<ApiResponse> {
    const { tool, processedArgs } = this.validateTool(name, args);
    
    switch (name) {
      case 'get_software_suggestions_by_product_ids':
        return await this.getSoftwareSuggestionsByProductIds(processedArgs);
      case 'get_software_releases_by_product_ids':
        return await this.getSoftwareReleasesByProductIds(processedArgs);
      case 'get_compatible_software_by_product_id':
        return await this.getCompatibleSoftwareByProductId(processedArgs);
      case 'get_software_suggestions_by_mdf_ids':
        return await this.getSoftwareSuggestionsByMdfIds(processedArgs);
      case 'get_software_releases_by_mdf_ids':
        return await this.getSoftwareReleasesByMdfIds(processedArgs);
      case 'get_compatible_software_by_mdf_id':
        return await this.getCompatibleSoftwareByMdfId(processedArgs);
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  private async getSoftwareSuggestionsByProductIds(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.page_index) params.pageIndex = args.page_index;

    const response = await this.makeApiCall(`/suggestions/software/productIds/${args.product_ids}`, params);
    
    return this.formatSoftwareSuggestionResponse(response, `Software Suggestions for Product IDs: ${args.product_ids}`);
  }

  private async getSoftwareReleasesByProductIds(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.page_index) params.pageIndex = args.page_index;

    const response = await this.makeApiCall(`/suggestions/releases/productIds/${args.product_ids}`, params);
    
    return this.formatSoftwareSuggestionResponse(response, `Software Releases for Product IDs: ${args.product_ids}`);
  }

  private async getCompatibleSoftwareByProductId(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.page_index) params.pageIndex = args.page_index;
    if (args.current_image) params.currentImage = args.current_image;
    if (args.current_release) params.currentRelease = args.current_release;

    const response = await this.makeApiCall(`/suggestions/compatible/productId/${args.product_id}`, params);
    
    return this.formatSoftwareSuggestionResponse(response, `Compatible Software for Product ID: ${args.product_id}`);
  }

  private async getSoftwareSuggestionsByMdfIds(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.page_index) params.pageIndex = args.page_index;

    const response = await this.makeApiCall(`/suggestions/software/mdfIds/${args.mdf_ids}`, params);
    
    return this.formatSoftwareSuggestionResponse(response, `Software Suggestions for MDF IDs: ${args.mdf_ids}`);
  }

  private async getSoftwareReleasesByMdfIds(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.page_index) params.pageIndex = args.page_index;

    const response = await this.makeApiCall(`/suggestions/releases/mdfIds/${args.mdf_ids}`, params);
    
    return this.formatSoftwareSuggestionResponse(response, `Software Releases for MDF IDs: ${args.mdf_ids}`);
  }

  private async getCompatibleSoftwareByMdfId(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.page_index) params.pageIndex = args.page_index;
    if (args.current_image) params.currentImage = args.current_image;
    if (args.current_release) params.currentRelease = args.current_release;

    const response = await this.makeApiCall(`/suggestions/compatible/mdfId/${args.mdf_id}`, params);
    
    return this.formatSoftwareSuggestionResponse(response, `Compatible Software for MDF ID: ${args.mdf_id}`);
  }

  private formatSoftwareSuggestionResponse(data: any, title: string): ApiResponse {
    if (!data || !data.productList || !Array.isArray(data.productList)) {
      return {
        error: 'No Software Suggestions Found',
        message: 'No software suggestions found for the specified product IDs.',
        data: null
      };
    }

    // Handle the actual API response structure with productList
    const formattedProducts = data.productList.map((productItem: any) => this.formatProductSuggestion(productItem));

    return {
      data: {
        title,
        count: data.productList.length,
        total_results: data.paginationResponseRecord?.totalRecords || data.productList.length,
        products: formattedProducts,
        pagination: data.paginationResponseRecord || null
      }
    };
  }

  private formatProductSuggestion(productItem: any): any {
    const product = productItem.product || {};
    const suggestions = productItem.suggestions || [];
    
    return {
      // Basic product identification
      product_id: product.basePID,
      product_name: product.productName,
      mdf_id: product.mdfId,
      software_type: product.softwareType,
      
      // Format all software suggestions for this product
      suggestions: suggestions.map((suggestion: any) => this.formatSuggestion(suggestion)),
      
      // Links
      software_download_url: this.generateSoftwareDownloadUrl(product.basePID),
      cisco_url: this.generateCiscoProductUrl(product.basePID)
    };
  }

  private formatSuggestion(suggestion: any): any {
    return {
      // Release information
      is_suggested: suggestion.isSuggested === 'Y',
      release_format: suggestion.releaseFormat1 || suggestion.releaseFormat2,
      release_date: suggestion.releaseDate,
      major_release: suggestion.majorRelease,
      release_train: suggestion.releaseTrain,
      release_lifecycle: suggestion.releaseLifeCycle,
      display_name: suggestion.relDispName,
      train_display_name: suggestion.trainDispName,
      
      // Image information
      images: this.formatImages(suggestion.images || [])
    };
  }


  private formatImages(images: any[]): any[] {
    if (!Array.isArray(images)) return [];
    
    return images.map((image: any) => ({
      image_name: image.imageName,
      image_size: image.imageSize,
      image_size_mb: image.imageSize ? Math.round(parseInt(image.imageSize) / 1024 / 1024) : null,
      feature_set: image.featureSet,
      description: image.description,
      required_dram: image.requiredDRAM,
      required_flash: image.requiredFlash
    }));
  }

  private generateSoftwareDownloadUrl(productId: string): string | null {
    if (!productId) return null;
    // Generate URL to Cisco's software download page
    return `https://software.cisco.com/download/navigator.html?mdfid=${encodeURIComponent(productId)}`;
  }

  private generateCiscoProductUrl(productId: string): string | null {
    if (!productId) return null;
    // Generate URL to Cisco's modern search page
    return `https://search.cisco.com/search?query=${encodeURIComponent(productId)}`;
  }

  // Override getResultCount for Software API responses
  protected getResultCount(data: ApiResponse): number {
    if (data.data && 'products' in data.data && Array.isArray(data.data.products)) {
      return data.data.products.length;
    }
    return 0;
  }
}