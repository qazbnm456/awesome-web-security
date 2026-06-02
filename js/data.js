typescript
/**
 * data.ts - Static data module for report summary and error details
 * 
 * Provides immutable data structures for client-side rendering of
 * web security scan results. All data is frozen to prevent mutation.
 * 
 * @module data
 */

import { createLogger, format, transports } from 'winston';

/**
 * Logger configuration for data module
 */
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.json()
  ),
  defaultMeta: { service: 'data-module' },
  transports: [
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.simple()
      )
    }),
    new transports.File({ 
      filename: 'logs/data-error.log', 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    new transports.File({ 
      filename: 'logs/data-combined.log',
      maxsize: 5242880,
      maxFiles: 5
    })
  ]
});

/**
 * Interface for report summary data structure
 */
export interface IReportSummary {
  readonly total: number;
  readonly successful: number;
  readonly timeouts: number;
  readonly redirected: number;
  readonly excluded: number;
  readonly unknown: number;
  readonly errors: number;
  readonly unsupported: number;
}

/**
 * Interface for status display configuration
 */
export interface IStatusConfig {
  readonly label: string;
  readonly color: string;
  readonly icon: string;
}

/**
 * Interface for error entry data structure
 */
export interface IErrorEntry {
  readonly file: string;
  readonly type: ErrorType;
  readonly message: string;
  readonly url: string;
  readonly detail?: string;
}

/**
 * Enum for error types to ensure type safety
 */
export enum ErrorType {
  ERROR = 'ERROR',
  NOT_FOUND = '404',
  TIMEOUT = 'TIMEOUT'
}

/**
 * Type for status keys
 */
export type StatusKey = keyof IReportSummary;

/**
 * Type for status config keys
 */
export type StatusConfigKey = keyof typeof statusConfig;

/**
 * Custom error class for data validation errors
 */
export class DataValidationError extends Error {
  constructor(
    message: string, 
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'DataValidationError';
    Object.setPrototypeOf(this, DataValidationError.prototype);
    logger.error(`DataValidationError: ${message}`, { code, details });
  }
}

/**
 * Custom error class for invalid status key errors
 */
export class InvalidStatusKeyError extends Error {
  constructor(key: string) {
    super(`Invalid status key: ${key}`);
    this.name = 'InvalidStatusKeyError';
    Object.setPrototypeOf(this, InvalidStatusKeyError.prototype);
    logger.warn(`InvalidStatusKeyError: ${key}`);
  }
}

/**
 * Custom error class for URL validation errors
 */
export class InvalidUrlError extends DataValidationError {
  constructor(url: string) {
    super(
      `Invalid URL provided: ${url}`,
      'INVALID_URL',
      { url }
    );
    this.name = 'InvalidUrlError';
    Object.setPrototypeOf(this, InvalidUrlError.prototype);
  }
}

/**
 * Report summary data from the scan results.
 * @constant
 */
export const reportSummary: Readonly<IReportSummary> = Object.freeze({
  total: 2605,
  successful: 1952,
  timeouts: 18,
  redirected: 151,
  excluded: 279,
  unknown: 0,
  errors: 205,
  unsupported: 0
});

/**
 * Status mapping for display and filtering.
 * Maps status codes to their display properties.
 * @constant
 */
export const statusConfig: Readonly<Record<StatusKey, IStatusConfig>> = Object.freeze({
  total: { label: 'Total', color: '#1a73e8', icon: '🔍' },
  successful: { label: 'Successful', color: '#34a853', icon: '✅' },
  timeouts: { label: 'Timeouts', color: '#ff6d01', icon: '⏳' },
  redirected: { label: 'Redirected', color: '#8e24aa', icon: '🔀' },
  excluded: { label: 'Excluded', color: '#9e9e9e', icon: '👻' },
  unknown: { label: 'Unknown', color: '#616161', icon: '❓' },
  errors: { label: 'Errors', color: '#ea4335', icon: '🚫' },
  unsupported: { label: 'Unsupported', color: '#616161', icon: '⛔' }
});

/**
 * Validates and sanitizes a string input
 * @param input - The string to validate
 * @param fieldName - Name of the field for error messages
 * @returns Sanitized string
 * @throws {DataValidationError} If validation fails
 */
function validateStringInput(input: string, fieldName: string): string {
  if (typeof input !== 'string') {
    throw new DataValidationError(
      `${fieldName} must be a string`,
      'INVALID_INPUT_TYPE',
      { field: fieldName, receivedType: typeof input }
    );
  }

  const trimmed = input.trim();
  
  if (trimmed.length === 0) {
    throw new DataValidationError(
      `${fieldName} cannot be empty`,
      'EMPTY_INPUT',
      { field: fieldName }
    );
  }

  if (trimmed.length > 10000) {
    throw new DataValidationError(
      `${fieldName} exceeds maximum length of 10000 characters`,
      'INPUT_TOO_LONG',
      { field: fieldName, length: trimmed.length }
    );
  }

  // Sanitize input to prevent XSS
  const sanitized = trimmed.replace(/[<>]/g, '');
  
  if (sanitized !== trimmed) {
    logger.warn(`Input sanitized for ${fieldName}: removed HTML characters`);
  }

  return sanitized;
}

/**
 * Validates a URL string
 * @param url - The URL to validate
 * @returns Validated URL string
 * @throws {InvalidUrlError} If URL is invalid
 */
function validateUrl(url: string): string {
  const sanitizedUrl = validateStringInput(url, 'URL');
  
  try {
    const parsedUrl = new URL(sanitizedUrl);
    
    // Additional security checks
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      throw new InvalidUrlError(sanitizedUrl);
    }
    
    // Check for potentially malicious URLs
    const blockedPatterns = [
      /^javascript:/i,
      /^data:/i,
      /^file:/i,
      /^vbscript:/i
    ];
    
    for (const pattern of blockedPatterns) {
      if (pattern.test(sanitizedUrl)) {
        throw new DataValidationError(
          'Potentially malicious URL detected',
          'MALICIOUS_URL',
          { url: sanitizedUrl, pattern: pattern.toString() }
        );
      }
    }
    
    return sanitizedUrl;
  } catch (error) {
    if (error instanceof DataValidationError) {
      throw error;
    }
    throw new InvalidUrlError(sanitizedUrl);
  }
}

/**
 * Creates a frozen error entry with validation
 * @param file - Source file name
 * @param type - Error type
 * @param message - Error message
 * @param url - Affected URL
 * @param detail - Optional additional details
 * @returns Frozen error entry
 * @throws {DataValidationError} If validation fails
 */
function createErrorEntry(
  file: string,
  type: ErrorType,
  message: string,
  url: string,
  detail?: string
): Readonly<IErrorEntry> {
  const startTime = Date.now();
  
  try {
    // Validate all required fields
    const validatedFile = validateStringInput(file, 'file');
    const validatedMessage = validateStringInput(message, 'message');
    const validatedUrl = validateUrl(url);
    
    // Validate error type
    if (!Object.values(ErrorType).includes(type)) {
      throw new DataValidationError(
        `Invalid error type: ${type}`,
        'INVALID_ERROR_TYPE',
        { type, validTypes: Object.values(ErrorType) }
      );
    }
    
    // Validate optional detail
    let validatedDetail: string | undefined;
    if (detail !== undefined) {
      validatedDetail = validateStringInput(detail, 'detail');
    }
    
    const entry: IErrorEntry = {
      file: validatedFile,
      type,
      message: validatedMessage,
      url: validatedUrl,
      detail: validatedDetail
    };
    
    logger.debug('Error entry created', { 
      file: validatedFile, 
      type, 
      url: validatedUrl,
      duration: Date.now() - startTime 
    });
    
    return Object.freeze(entry);
  } catch (error) {
    logger.error('Failed to create error entry', {
      file,
      type,
      url,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    throw error;
  }
}

/**
 * Detailed error entries grouped by source file.
 * Each entry contains the error type, message, and affected URL.
 * @constant
 */
export const errorDetails: ReadonlyArray<Readonly<IErrorEntry>> = Object.freeze([
  createErrorEntry(
    'README-jp.md',
    ErrorType.ERROR,
    'Network error: Connection failed. Check network connectivity and firewall settings',
    'http://blog.safebuff.com/2016/07/03/SSRF-Tips/',
    'error sending request for url (http://blog.safebuff.com/2016/07/03/SSRF-Tips/): Connection failed. Check network connectivity and firewall settings'
  ),
  createErrorEntry(
    'README-jp.md',
    ErrorType.ERROR,
    'Network error: Connection failed. Check network connectivity and firewall settings',
    'http://blog.safebuff.com/',
    'error sending request for url (http://blog.safebuff.com/): Connection failed. Check network connectivity and firewall settings'
  ),
  createErrorEntry(
    'README-jp.md',
    ErrorType.ERROR,
    'Network error: Connection failed. Check network connectivity and firewall settings',
    'http://blogs.360.cn/360safe/2016/11/29/three-roads-lead-to-rome-2/',
    'error sending request for url (http://blogs.360.cn/360safe/2016/11/29/three-roads-lead-to-rome-2/): Connection failed. Check network connectivity and firewall settings'
  ),
  createErrorEntry(
    'README-jp.md',
    ErrorType.NOT_FOUND,
    'Rejected status code: 404 Not Found (configurable with "accept" option)',
    'http://blog.safebuff.com/2016/07/03/SSRF-Tips/',
    'HTTP 404 Not Found'
  ),
  createErrorEntry(
    'README-jp.md',
    ErrorType.TIMEOUT,
    'Timeout',
    'http://blog.safebuff.com/',
    'Request timed out after configured duration'
  ),
  createErrorEntry(
    'README-jp.md',
    ErrorType.ERROR,
    'Network error: Connection failed. Check network connectivity and firewall settings',
    'http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html',
    'error sending request for url (http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html): Connection failed. Check network connectivity and firewall settings'
  ),
  createErrorEntry(
    'README-jp.md',
    ErrorType.ERROR,
    'Network error: Connection failed. Check network connectivity and firewall settings',
    'http://lab.onsec.ru/',
    'error sending request for url (http://lab.onsec.ru/): Connection failed. Check network connectivity and firewall settings'
  ),
  createErrorEntry(
    'README-jp.md',
    ErrorType.TIMEOUT,
    'Timeout',
    'http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html',
    'Request timed out after configured duration'
  ),
  createErrorEntry(
    'README-jp.md',
    ErrorType.NOT_FOUND,
    'Rejected status code: 404 Not Found (configurable with "accept" option)',
    'http://blogs.360.cn/360safe/2016/11/29/three-roads-lead-to-rome-2/',
    'HTTP 404 Not Found'
  ),
  createErrorEntry(
    'README-jp.md',
    ErrorType.NOT_FOUND,
    'Rejected status code: 404 Not Found (configurable with "accept" option)',
    'http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html',
    'HTTP 404 Not Found'
  ),
  createErrorEntry(
    'README-jp.md',
    ErrorType.NOT_FOUND,
    'Rejected status code: 404 Not Found (configurable with "accept" option)',
    'http://lab.onsec.ru/',
    'HTTP 404 Not Found'
  )
]);

/**
 * Returns the count for a given status key.
 * @param statusKey - The status key (e.g., 'total', 'successful')
 * @returns The count for the given status
 * @throws {InvalidStatusKeyError} If the status key is invalid
 */
export function getStatusCount(statusKey: StatusKey): number {
  const startTime = Date.now();
  
  try {
    if (!(statusKey in reportSummary)) {
      throw new InvalidStatusKeyError(statusKey);
    }
    
    const count = reportSummary[statusKey];
    
    logger.debug('Status count retrieved', {
      statusKey,
      count,
      duration: Date.now() - startTime
    });
    
    return count;
  } catch (error) {
    logger.error('Failed to get status count', {
      statusKey,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    throw error;
  }
}

/**
 * Returns the status configuration for a given status key.
 * @param statusKey - The status key
 * @returns Status display config
 * @throws {InvalidStatusKeyError} If the status key is invalid
 */
export function getStatusConfig(statusKey: StatusConfigKey): Readonly<IStatusConfig> {
  const startTime = Date.now();
  
  try {
    if (!(statusKey in statusConfig)) {
      throw new InvalidStatusKeyError(statusKey);
    }
    
    const config = statusConfig[statusKey];
    
    logger.debug('Status config retrieved', {
      statusKey,
      label: config.label,
      duration: Date.now() - startTime
    });
    
    return config;
  } catch (error) {
    logger.error('Failed to get status config', {
      statusKey,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    throw error;
  }
}

/**
 * Filters error details by file name.
 * @param fileName - The file name to filter by
 * @returns Filtered array of error entries
 * @throws {DataValidationError} If fileName is invalid
 */
export function filterErrorsByFile(fileName: string): ReadonlyArray<Readonly<IErrorEntry>> {
  const startTime = Date.now();
  
  try {
    const validatedFileName = validateStringInput(fileName, 'fileName');
    
    const filtered = errorDetails.filter(
      (entry: Readonly<IErrorEntry>) => entry.file === validatedFileName
    );
    
    logger.debug('Errors filtered by file', {
      fileName: validatedFileName,
      count: filtered.length,
      duration: Date.now() - startTime
    });
    
    return Object.freeze(filtered);
  } catch (error) {
    logger.error('Failed to filter errors by file', {
      fileName,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    throw error;
  }
}

/**
 * Filters error details by error type.
 * @param errorType - The error type to filter by
 * @returns Filtered array of error entries
 * @throws {DataValidationError} If errorType is invalid
 */
export function filterErrorsByType(errorType: ErrorType): ReadonlyArray<Readonly<IErrorEntry>> {
  const startTime = Date.now();
  
  try {
    if (!Object.values(ErrorType).includes(errorType)) {
      throw new DataValidationError(
        `Invalid error type: ${errorType}`,
        'INVALID_ERROR_TYPE',
        { errorType, validTypes: Object.values(ErrorType) }
      );
    }
    
    const filtered = errorDetails.filter(
      (entry: Readonly<IErrorEntry>) => entry.type === errorType
    );
    
    logger.debug('Errors filtered by type', {
      errorType,
      count: filtered.length,
      duration: Date.now() - startTime
    });
    
    return Object.freeze(filtered);
  } catch (error) {
    logger.error('Failed to filter errors by type', {
      errorType,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    throw error;
  }
}

/**
 * Gets summary statistics for error details.
 * @returns Object containing error statistics
 */
export function getErrorStatistics(): Readonly<{
  totalErrors: number;
  errorsByFile: Record<string, number>;
  errorsByType: Record<ErrorType, number>;
  uniqueUrls: number;
}> {
  const startTime = Date.now();
  
  try {
    const errorsByFile: Record<string, number> = {};
    const errorsByType: Record<ErrorType, number> = {
      [ErrorType.ERROR]: 0,
      [ErrorType.NOT_FOUND]: 0,
      [ErrorType.TIMEOUT]: 0
    };
    const uniqueUrls = new Set<string>();
    
    for (const entry of errorDetails) {
      // Count by file
      errorsByFile[entry.file] = (errorsByFile[entry.file] || 0) + 1;
      
      // Count by type
      errorsByType[entry.type] = (errorsByType[entry.type] || 0) + 1;
      
      // Track unique URLs
      uniqueUrls.add(entry.url);
    }
    
    const statistics = Object.freeze({
      totalErrors: errorDetails.length,
      errorsByFile: Object.freeze(errorsByFile),
      errorsByType: Object.freeze