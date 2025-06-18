// Logger interface
export interface Logger {
  info: (message: string, data?: any) => void;
  error: (message: string, data?: any) => void;
  warn: (message: string, data?: any) => void;
}

// Logger implementation - can be controlled externally
let loggingEnabled = true;

export const logger: Logger = {
  info: (message: string, data?: any) => {
    if (loggingEnabled) {
      const timestamp = new Date().toISOString();
      const logEntry = { timestamp, level: 'info', message, ...(data && { data }) };
      console.log(JSON.stringify(logEntry));
    }
  },
  error: (message: string, data?: any) => {
    if (loggingEnabled) {
      const timestamp = new Date().toISOString();
      const logEntry = { timestamp, level: 'error', message, ...(data && { data }) };
      console.error(JSON.stringify(logEntry));
    }
  },
  warn: (message: string, data?: any) => {
    if (loggingEnabled) {
      const timestamp = new Date().toISOString();
      const logEntry = { timestamp, level: 'warn', message, ...(data && { data }) };
      console.warn(JSON.stringify(logEntry));
    }
  }
};

// Control logging externally
export function setLogging(enabled: boolean) {
  loggingEnabled = enabled;
}