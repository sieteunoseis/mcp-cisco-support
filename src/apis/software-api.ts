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
        name: 'get_basic_suggestions_by_product_ids',
        title: 'Get Basic Suggestions by Product IDs',
        description: 'Get basic software suggestions for specified product IDs. Provides general software recommendation information.',
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
      case 'get_basic_suggestions_by_product_ids':
        return await this.getBasicSuggestionsByProductIds(processedArgs);
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

  private async getBasicSuggestionsByProductIds(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.page_index) params.pageIndex = args.page_index;

    const response = await this.makeApiCall(`/suggestions/productIds/${args.product_ids}`, params);
    
    return this.formatSoftwareSuggestionResponse(response, `Basic Suggestions for Product IDs: ${args.product_ids}`);
  }

  private formatSoftwareSuggestionResponse(data: any, title: string): ApiResponse {
    if (!data || (!data.suggestions && !data.productList && !data.products)) {
      return {
        error: 'No Software Suggestions Found',
        message: 'No software suggestions found for the specified product IDs.',
        data: null
      };
    }

    // Handle different response formats from the Software Suggestion API
    const suggestions = data.suggestions || data.productList || data.products || [];
    const formattedSuggestions = suggestions.map((suggestion: any) => this.formatSuggestion(suggestion));

    return {
      data: {
        title,
        count: suggestions.length,
        total_results: data.total_results || suggestions.length,
        suggestions: formattedSuggestions,
        pagination: data.pagination_info || null
      }
    };
  }

  private formatSuggestion(suggestion: any): any {
    return {
      // Basic product identification
      product_id: suggestion.product_id || suggestion.productId || suggestion.basePID,
      product_name: suggestion.product_name || suggestion.productName || suggestion.name,
      
      // Software recommendations
      recommended_release: suggestion.recommended_release || suggestion.recommendedRelease || suggestion.suggestedRelease,
      current_release: suggestion.current_release || suggestion.currentRelease,
      latest_release: suggestion.latest_release || suggestion.latestRelease,
      
      // Release details
      releases: this.formatReleases(suggestion.releases || suggestion.softwareReleases || []),
      
      // Image information (if available)
      images: this.formatImages(suggestion.images || suggestion.softwareImages || []),
      
      // Metadata
      suggestion_type: suggestion.suggestion_type || suggestion.suggestionType || suggestion.type,
      last_updated: suggestion.last_updated || suggestion.lastUpdated || suggestion.updated_date,
      
      // Links
      software_download_url: this.generateSoftwareDownloadUrl(suggestion.product_id || suggestion.productId || suggestion.basePID),
      cisco_url: this.generateCiscoProductUrl(suggestion.product_id || suggestion.productId || suggestion.basePID)
    };
  }

  private formatReleases(releases: any[]): any[] {
    if (!Array.isArray(releases)) return [];
    
    return releases.map((release: any) => ({
      release_version: release.release_version || release.releaseVersion || release.version,
      release_date: release.release_date || release.releaseDate || release.date,
      recommendation_level: release.recommendation_level || release.recommendationLevel || release.level,
      status: release.status || release.releaseStatus,
      description: release.description || release.releaseDescription,
      is_suggested: release.is_suggested || release.isSuggested || release.suggested || false,
      is_latest: release.is_latest || release.isLatest || release.latest || false
    }));
  }

  private formatImages(images: any[]): any[] {
    if (!Array.isArray(images)) return [];
    
    return images.map((image: any) => ({
      image_name: image.image_name || image.imageName || image.name,
      image_version: image.image_version || image.imageVersion || image.version,
      image_type: image.image_type || image.imageType || image.type,
      file_size: image.file_size || image.fileSize || image.size,
      checksum: image.checksum || image.md5,
      download_url: image.download_url || image.downloadUrl || image.url,
      release_notes_url: image.release_notes_url || image.releaseNotesUrl
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
    if ('suggestions' in data && Array.isArray(data.suggestions)) {
      return data.suggestions.length;
    }
    if ('productList' in data && Array.isArray(data.productList)) {
      return data.productList.length;
    }
    if ('products' in data && Array.isArray(data.products)) {
      return data.products.length;
    }
    return 0;
  }
}