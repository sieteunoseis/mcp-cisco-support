/**
 * Validate tool arguments against the tool's JSON Schema (the subset our
 * schemas use: type, enum, minimum, maximum, items, required, and no unknown
 * properties). Errors name the argument and the allowed values so the model
 * can correct the call.
 */
type Schema = {
  type?: string;
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  items?: Schema;
  properties?: Record<string, Schema>;
  required?: string[];
};

function checkValue(name: string, value: unknown, schema: Schema, errors: string[]): void {
  const t = schema.type;
  if (t === 'integer' || t === 'number') {
    const n = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
    if (typeof n !== 'number' || Number.isNaN(n) || (t === 'integer' && !Number.isInteger(n))) {
      errors.push(`${name} must be ${t === 'integer' ? 'an integer' : 'a number'}`);
      return;
    }
    if (schema.minimum !== undefined && n < schema.minimum) errors.push(`${name} must be >= ${schema.minimum}`);
    if (schema.maximum !== undefined && n > schema.maximum) errors.push(`${name} must be <= ${schema.maximum}`);
    return;
  }
  if (t === 'boolean' && typeof value !== 'boolean' && value !== 'true' && value !== 'false') {
    errors.push(`${name} must be true or false`);
    return;
  }
  if (t === 'array') {
    // Accept a single value where an array is expected (e.g. severity: "1")
    const items = Array.isArray(value) ? value : [value];
    if (schema.items) items.forEach((item, i) => checkValue(`${name}[${i}]`, item, schema.items!, errors));
    return;
  }
  if (t === 'string' && typeof value !== 'string' && typeof value !== 'number') {
    errors.push(`${name} must be a string`);
    return;
  }
  if (schema.enum && !schema.enum.map(String).includes(String(value))) {
    errors.push(`${name} must be one of: ${schema.enum.join(', ')}`);
  }
}

export function validateArgs(schema: Schema, args: Record<string, unknown>): void {
  const errors: string[] = [];
  const props = schema.properties ?? {};
  for (const key of schema.required ?? []) {
    if (args[key] === undefined || args[key] === null || args[key] === '') errors.push(`${key} is required`);
  }
  for (const [key, value] of Object.entries(args)) {
    if (value === undefined || value === null) continue;
    const prop = props[key];
    if (!prop) {
      errors.push(`unknown argument "${key}" (allowed: ${Object.keys(props).join(', ')})`);
      continue;
    }
    checkValue(key, value, prop, errors);
  }
  if (errors.length) throw new Error(`Invalid arguments: ${errors.join('; ')}`);
}
