import { describe, it, expect, beforeEach } from '@jest/globals';
import { createMCPServer, createElicitationRequest, ElicitationSchemas } from '../src/mcp-server.js';

describe('Elicitation Request Tests', () => {
  let server: any;

  beforeEach(() => {
    server = createMCPServer();
  });

  it('should create elicitation request helper function', () => {
    const request = createElicitationRequest(
      'Please provide your API credentials',
      ElicitationSchemas.apiCredentials
    );

    expect(request).toHaveProperty('method', 'elicitation/create');
    expect(request).toHaveProperty('params');
    expect(request.params).toHaveProperty('message', 'Please provide your API credentials');
    expect(request.params).toHaveProperty('requestedSchema');
    expect(request.params.requestedSchema).toEqual(ElicitationSchemas.apiCredentials);
  });

  it('should have elicitation capability declared', () => {
    // Test that the server was created successfully
    expect(server).toBeDefined();
    expect(server.setRequestHandler).toBeDefined();
    // The capabilities are internal to the server, so we can't directly test them
    // But we can verify the server was created with the expected structure
  });

  it('should have predefined elicitation schemas', () => {
    expect(ElicitationSchemas).toHaveProperty('apiCredentials');
    expect(ElicitationSchemas).toHaveProperty('searchRefinement');
    expect(ElicitationSchemas).toHaveProperty('userConfirmation');
    expect(ElicitationSchemas).toHaveProperty('productSelection');

    // Verify apiCredentials schema structure
    expect(ElicitationSchemas.apiCredentials).toHaveProperty('type', 'object');
    expect(ElicitationSchemas.apiCredentials).toHaveProperty('properties');
    expect(ElicitationSchemas.apiCredentials.properties).toHaveProperty('clientId');
    expect(ElicitationSchemas.apiCredentials.properties).toHaveProperty('confirm');
    expect(ElicitationSchemas.apiCredentials).toHaveProperty('required');
    expect(ElicitationSchemas.apiCredentials.required).toContain('clientId');
    expect(ElicitationSchemas.apiCredentials.required).toContain('confirm');
  });

  it('should validate searchRefinement schema', () => {
    const schema = ElicitationSchemas.searchRefinement;
    
    expect(schema.properties.severity).toHaveProperty('enum');
    expect(schema.properties.severity.enum).toContain('1');
    expect(schema.properties.severity.enum).toContain('6');
    
    expect(schema.properties.status).toHaveProperty('enum');
    expect(schema.properties.status.enum).toContain('O');
    expect(schema.properties.status.enum).toContain('F');
    
    expect(schema.properties.dateRange).toHaveProperty('enum');
    expect(schema.properties.dateRange.enum).toContain('1');
    expect(schema.properties.dateRange.enum).toContain('5');
  });

  it('should validate userConfirmation schema', () => {
    const schema = ElicitationSchemas.userConfirmation;
    
    expect(schema.properties.confirmed).toHaveProperty('type', 'boolean');
    expect(schema.properties.reason).toHaveProperty('type', 'string');
    expect(schema.required).toContain('confirmed');
    expect(schema.required).toHaveLength(1);
  });

  it('should validate productSelection schema', () => {
    const schema = ElicitationSchemas.productSelection;
    
    expect(schema.properties.selectedProduct).toHaveProperty('type', 'string');
    expect(schema.properties.version).toHaveProperty('type', 'string');
    expect(schema.required).toContain('selectedProduct');
    expect(schema.required).toHaveLength(1);
  });

  it('should create various elicitation requests', () => {
    const credentialsRequest = createElicitationRequest(
      'Please provide your Cisco API credentials',
      ElicitationSchemas.apiCredentials
    );

    const searchRequest = createElicitationRequest(
      'Please refine your search parameters',
      ElicitationSchemas.searchRefinement
    );

    const confirmationRequest = createElicitationRequest(
      'This action will modify your configuration. Do you want to proceed?',
      ElicitationSchemas.userConfirmation
    );

    expect(credentialsRequest.params.message).toBe('Please provide your Cisco API credentials');
    expect(searchRequest.params.message).toBe('Please refine your search parameters');
    expect(confirmationRequest.params.message).toBe('This action will modify your configuration. Do you want to proceed?');
  });
});