import { logger } from './logger.js';

// Web search integration for product information resolution
export class WebSearchHelper {
  /**
   * Resolve product ID to full product name using web search
   */
  static async resolveProductName(productId: string): Promise<{
    fullName: string | null;
    modelUrl: string | null;
    searchStrategy: string[];
  }> {
    const result = {
      fullName: null as string | null,
      modelUrl: null as string | null,
      searchStrategy: [] as string[]
    };

    try {
      logger.info('Attempting to resolve product name via web search', { productId });
      
      // Strategy 1: Direct Cisco support search
      result.searchStrategy.push(`Web search for "${productId}" site:cisco.com/support`);
      
      // Strategy 2: Product specifications search
      result.searchStrategy.push(`Web search for "${productId} datasheet" site:cisco.com`);
      
      // Strategy 3: General Cisco search
      result.searchStrategy.push(`Web search for "Cisco ${productId}" official documentation`);

      // Known product mappings based on patterns
      const knownMappings = this.getKnownProductMappings();
      const mapping = knownMappings[productId.toUpperCase()];
      
      if (mapping) {
        result.fullName = mapping.fullName;
        result.modelUrl = mapping.modelUrl;
        result.searchStrategy.push('Resolved using known product mapping database');
        logger.info('Product resolved via known mappings', { productId, fullName: result.fullName });
        return result;
      }

      // Pattern-based resolution for ISR series
      if (productId.match(/^ISR44\d+/i)) {
        const model = productId.replace(/\/K9$/i, '');
        result.fullName = `Cisco ${model} Integrated Services Router`;
        result.modelUrl = `https://www.cisco.com/c/en/us/support/routers/${model.toLowerCase()}-integrated-services-router-isr/model.html`;
        result.searchStrategy.push('Resolved using ISR series pattern matching');
        logger.info('ISR product resolved via pattern matching', { productId, fullName: result.fullName });
        return result;
      }

      // Pattern-based resolution for Catalyst switches
      if (productId.match(/^(WS-)?C\d+/i)) {
        const model = productId.replace(/^WS-/, '').replace(/\/K9$/i, '');
        result.fullName = `Cisco Catalyst ${model} Switch`;
        result.searchStrategy.push('Resolved using Catalyst series pattern matching');
        logger.info('Catalyst product resolved via pattern matching', { productId, fullName: result.fullName });
        return result;
      }

      // Pattern-based resolution for ASR series
      if (productId.match(/^ASR\d+/i)) {
        const model = productId.replace(/\/K9$/i, '');
        result.fullName = `Cisco ${model} Series Aggregation Services Router`;
        result.searchStrategy.push('Resolved using ASR series pattern matching');
        logger.info('ASR product resolved via pattern matching', { productId, fullName: result.fullName });
        return result;
      }

      logger.warn('Could not resolve product name', { productId });
      return result;

    } catch (error) {
      logger.error('Web search resolution failed', { 
        productId, 
        error: error instanceof Error ? error.message : error 
      });
      return result;
    }
  }

  /**
   * Generate web search queries for product lifecycle information
   */
  static generateLifecycleSearchQueries(productId: string, softwareVersion?: string): string[] {
    const queries = [];
    
    // End-of-life searches
    queries.push(`"${productId}" end of life site:cisco.com`);
    queries.push(`"${productId}" EoL announcement site:cisco.com`);
    queries.push(`"${productId}" end of sale site:cisco.com`);
    
    if (softwareVersion) {
      queries.push(`"${softwareVersion}" end of life end of support site:cisco.com`);
      queries.push(`IOS XE "${softwareVersion}" lifecycle site:cisco.com`);
    }
    
    // Migration and replacement searches
    queries.push(`"${productId}" replacement migration site:cisco.com`);
    queries.push(`"${productId}" successor product site:cisco.com`);
    
    return queries;
  }

  /**
   * Generate comprehensive search strategy for incident investigation
   */
  static generateIncidentSearchStrategy(productId: string, softwareVersion?: string, symptom?: string): {
    bugSearchTerms: string[];
    webSearchQueries: string[];
    recommendedApproach: string[];
  } {
    const bugSearchTerms = [];
    const webSearchQueries = [];
    const recommendedApproach = [];

    // Bug database search terms
    if (symptom) {
      bugSearchTerms.push(symptom);
      bugSearchTerms.push(`${productId} ${symptom}`);
      if (softwareVersion) {
        bugSearchTerms.push(`${symptom} ${softwareVersion}`);
      }
    }
    
    bugSearchTerms.push(productId);
    if (softwareVersion) {
      bugSearchTerms.push(`${productId} ${softwareVersion}`);
    }

    // Web search queries for additional context
    if (symptom) {
      webSearchQueries.push(`"${symptom}" "${productId}" site:cisco.com`);
      webSearchQueries.push(`"${symptom}" troubleshooting site:cisco.com`);
    }
    
    webSearchQueries.push(`"${productId}" known issues site:cisco.com`);
    if (softwareVersion) {
      webSearchQueries.push(`"${softwareVersion}" release notes problems site:cisco.com`);
    }

    // Recommended search approach
    recommendedApproach.push('1. Search bug database with specific symptom keywords');
    recommendedApproach.push('2. Search bug database by product ID and version');
    recommendedApproach.push('3. Use progressive search to try broader terms if no results');
    recommendedApproach.push('4. Web search for official Cisco documentation and release notes');
    recommendedApproach.push('5. Check end-of-life status if version is older');

    return {
      bugSearchTerms,
      webSearchQueries,
      recommendedApproach
    };
  }

  /**
   * Known product mappings for common Cisco products
   */
  private static getKnownProductMappings(): Record<string, { fullName: string; modelUrl: string; productSeries?: string; }> {
    return {
      'ISR4431/K9': {
        fullName: 'Cisco 4431 Integrated Services Router',
        modelUrl: 'https://www.cisco.com/c/en/us/support/routers/4431-integrated-services-router-isr/model.html',
        productSeries: 'Cisco 4000 Series Integrated Services Routers'
      },
      'ISR4431': {
        fullName: 'Cisco 4431 Integrated Services Router',
        modelUrl: 'https://www.cisco.com/c/en/us/support/routers/4431-integrated-services-router-isr/model.html',
        productSeries: 'Cisco 4000 Series Integrated Services Routers'
      },
      'ISR4451/K9': {
        fullName: 'Cisco 4451 Integrated Services Router', 
        modelUrl: 'https://www.cisco.com/c/en/us/support/routers/4451-integrated-services-router-isr/model.html',
        productSeries: 'Cisco 4000 Series Integrated Services Routers'
      },
      'ISR4451': {
        fullName: 'Cisco 4451 Integrated Services Router', 
        modelUrl: 'https://www.cisco.com/c/en/us/support/routers/4451-integrated-services-router-isr/model.html',
        productSeries: 'Cisco 4000 Series Integrated Services Routers'
      },
      'ISR4461/K9': {
        fullName: 'Cisco 4461 Integrated Services Router',
        modelUrl: 'https://www.cisco.com/c/en/us/support/routers/4461-integrated-services-router-isr/model.html',
        productSeries: 'Cisco 4000 Series Integrated Services Routers'
      },
      'C9200-24T': {
        fullName: 'Cisco Catalyst 9200 Series 24-Port Gigabit Switch',
        modelUrl: 'https://www.cisco.com/c/en/us/support/switches/catalyst-9200-series-switches/series.html',
        productSeries: 'Cisco Catalyst 9200 Series'
      },
      'ASR1001-X': {
        fullName: 'Cisco ASR 1001-X Series Aggregation Services Router',
        modelUrl: 'https://www.cisco.com/c/en/us/support/routers/asr-1001-x-router/model.html',
        productSeries: 'Cisco ASR 1000 Series'
      },
      'CUCM': {
        fullName: 'Cisco Unified Communications Manager',
        modelUrl: 'https://www.cisco.com/c/en/us/support/unified-communications/unified-communications-manager-callmanager/series.html',
        productSeries: 'Cisco Unified Communications Manager (CallManager)'
      },
      'CallManager': {
        fullName: 'Cisco Unified Communications Manager',
        modelUrl: 'https://www.cisco.com/c/en/us/support/unified-communications/unified-communications-manager-callmanager/series.html',
        productSeries: 'Cisco Unified Communications Manager (CallManager)'
      }
    };
  }

  /**
   * Convert version to Cisco API format (remove leading zeros)
   * 17.09.06 -> 17.9.6
   * 15.01.04 -> 15.1.4
   */
  static formatVersionForCiscoAPI(version: string): string {
    return version.replace(/\.0+(\d)/g, '.$1');
  }

  /**
   * Get the product series name for bug API searches
   */
  static getProductSeries(productId: string): string | null {
    const mappings = this.getKnownProductMappings();
    const mapping = mappings[productId.toUpperCase()];
    
    if (mapping?.productSeries) {
      return mapping.productSeries;
    }

    // Pattern-based resolution for ISR series
    if (productId.match(/^ISR44\d+/i)) {
      return 'Cisco 4000 Series Integrated Services Routers';
    }

    // Pattern-based resolution for Catalyst switches
    if (productId.match(/^(WS-)?C92\d+/i)) {
      return 'Cisco Catalyst 9200 Series';
    }

    // Pattern-based resolution for ASR series
    if (productId.match(/^ASR10\d+/i)) {
      return 'Cisco ASR 1000 Series';
    }

    // Pattern-based resolution for UC Manager
    if (productId.match(/^(CUCM|CallManager|Unified.*Communications.*Manager)/i)) {
      return 'Cisco Unified Communications Manager (CallManager)';
    }

    return null;
  }
}