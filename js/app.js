javascript
/**
 * js/app.js - Core Application Logic
 * 
 * Handles data parsing, filtering, sorting, chart rendering,
 * expandable error details, and responsive behavior.
 * 
 * Architecture: Vanilla JS, no frameworks.
 * Dependencies: Chart.js (CDN), Google Fonts (Inter)
 * 
 * @module app
 * @version 2.1.0
 */

'use strict';

// ---------------------------------------------------------------------------
// Imports & Polyfills
// ---------------------------------------------------------------------------

/**
 * Polyfill for Array.from for older browsers.
 * @param {*} arrayLike - Array-like object to convert
 * @param {Function} [mapFn] - Map function
 * @param {*} [thisArg] - This context for map function
 * @returns {Array}
 */
if (!Array.from) {
  Array.from = (function() {
    const toStr = Object.prototype.toString;
    const isCallable = fn => typeof fn === 'function' || toStr.call(fn) === '[object Function]';
    const toInteger = value => {
      const number = Number(value);
      if (isNaN(number)) return 0;
      if (number === 0 || !isFinite(number)) return number;
      return (number > 0 ? 1 : -1) * Math.floor(Math.abs(number));
    };
    const maxSafeInteger = Math.pow(2, 53) - 1;
    const toLength = value => {
      const len = toInteger(value);
      return Math.min(Math.max(len, 0), maxSafeInteger);
    };
    return function from(arrayLike, mapFn, thisArg) {
      const C = this;
      const items = Object(arrayLike);
      if (arrayLike == null) {
        throw new TypeError('Array.from requires an array-like object');
      }
      const mapFnIsCallable = typeof mapFn === 'function';
      let T;
      if (mapFnIsCallable) {
        T = thisArg;
      }
      const len = toLength(items.length);
      const A = isCallable(C) ? Object(new C(len)) : new Array(len);
      for (let i = 0; i < len; i++) {
        const value = items[i];
        if (mapFnIsCallable) {
          A[i] = mapFn.call(T, value, i, items);
        } else {
          A[i] = value;
        }
      }
      A.length = len;
      return A;
    };
  })();
}

// ---------------------------------------------------------------------------
// Constants & Configuration
// ---------------------------------------------------------------------------

/** @enum {string} */
const StatusType = Object.freeze({
  SUCCESS: 'success',
  TIMEOUT: 'timeout',
  REDIRECT: 'redirect',
  EXCLUDED: 'excluded',
  UNKNOWN: 'unknown',
  ERROR: 'error',
  UNSUPPORTED: 'unsupported'
});

/** @enum {string} */
const StatusSymbol = Object.freeze({
  SUCCESS: '✅',
  TIMEOUT: '⏳',
  REDIRECT: '🔀',
  EXCLUDED: '👻',
  UNKNOWN: '❓',
  ERROR: '🚫',
  UNSUPPORTED: '⛔'
});

/** @enum {string} */
const SortField = Object.freeze({
  STATUS: 'status',
  TITLE: 'title',
  URL: 'url',
  TIMESTAMP: 'timestamp',
  ERROR_TYPE: 'errorType'
});

/** @enum {string} */
const SortOrder = Object.freeze({
  ASC: 'asc',
  DESC: 'desc'
});

/** @enum {string} */
const FilterType = Object.freeze({
  ALL: 'all',
  SUCCESS: 'success',
  TIMEOUT: 'timeout',
  REDIRECT: 'redirect',
  EXCLUDED: 'excluded',
  UNKNOWN: 'unknown',
  ERROR: 'error',
  UNSUPPORTED: 'unsupported'
});

const CONFIG = Object.freeze({
  colors: {
    primary: '#1a73e8',
    success: '#34a853',
    timeout: '#ff6d01',
    redirect: '#8e24aa',
    excluded: '#9e9e9e',
    unknown: '#616161',
    error: '#ea4335',
    unsupported: '#000000',
    background: '#f8f9fa',
    surface: '#ffffff',
    textPrimary: '#202124',
    textSecondary: '#5f6368',
    border: '#dadce0',
    hover: '#e8f0fe'
  },
  statusMap: {
    [StatusSymbol.SUCCESS]: StatusType.SUCCESS,
    [StatusSymbol.TIMEOUT]: StatusType.TIMEOUT,
    [StatusSymbol.REDIRECT]: StatusType.REDIRECT,
    [StatusSymbol.EXCLUDED]: StatusType.EXCLUDED,
    [StatusSymbol.UNKNOWN]: StatusType.UNKNOWN,
    [StatusSymbol.ERROR]: StatusType.ERROR,
    [StatusSymbol.UNSUPPORTED]: StatusType.UNSUPPORTED
  },
  statusColors: {
    [StatusType.SUCCESS]: '#34a853',
    [StatusType.TIMEOUT]: '#ff6d01',
    [StatusType.REDIRECT]: '#8e24aa',
    [StatusType.EXCLUDED]: '#9e9e9e',
    [StatusType.UNKNOWN]: '#616161',
    [StatusType.ERROR]: '#ea4335',
    [StatusType.UNSUPPORTED]: '#000000'
  },
  chartDefaults: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          padding: 20,
          usePointStyle: true,
          font: { family: "'Inter', sans-serif", size: 12 }
        }
      },
      tooltip: {
        enabled: true,
        mode: 'index',
        intersect: false,
        backgroundColor: 'rgba(0,0,0,0.8)',
        titleFont: { family: "'Inter', sans-serif", size: 14 },
        bodyFont: { family: "'Inter', sans-serif", size: 12 },
        padding: 12,
        cornerRadius: 8
      }
    },
    animation: {
      duration: 500,
      easing: 'easeOutQuart'
    },
    hover: {
      mode: 'nearest',
      intersect: true
    }
  },
  debounceDelay: 300,
  maxRetries: 3,
  retryDelay: 1000,
  localStorageKey: 'awesome-web-security-state',
  apiEndpoint: '/api/status',
  refreshInterval: 300000 // 5 minutes
});

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

/**
 * Application logger with severity levels.
 * @class
 */
class Logger {
  /**
   * @param {string} context - Logger context name
   * @param {Object} [options] - Logger options
   * @param {boolean} [options.enabled=true] - Enable/disable logging
   * @param {string} [options.level='info'] - Minimum log level
   */
  constructor(context, options = {}) {
    /** @type {string} */
    this.context = context;
    /** @type {boolean} */
    this.enabled = options.enabled !== false;
    /** @type {string} */
    this.level = options.level || 'info';
    
    /** @enum {number} */
    this.levels = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3,
      fatal: 4
    };
  }

  /**
   * Check if log level should be output.
   * @param {string} level - Log level to check
   * @returns {boolean}
   * @private
   */
  _shouldLog(level) {
    if (!this.enabled) return false;
    return this.levels[level] >= this.levels[this.level];
  }

  /**
   * Format log message.
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @param {Object} [data] - Additional data
   * @returns {string}
   * @private
   */
  _format(level, message, data) {
    const timestamp = new Date().toISOString();
    const dataStr = data ? ` ${JSON.stringify(data)}` : '';
    return `[${timestamp}] [${level.toUpperCase()}] [${this.context}] ${message}${dataStr}`;
  }

  /**
   * Log debug message.
   * @param {string} message - Debug message
   * @param {Object} [data] - Additional data
   */
  debug(message, data) {
    if (this._shouldLog('debug')) {
      console.debug(this._format('debug', message, data));
    }
  }

  /**
   * Log info message.
   * @param {string} message - Info message
   * @param {Object} [data] - Additional data
   */
  info(message, data) {
    if (this._shouldLog('info')) {
      console.info(this._format('info', message, data));
    }
  }

  /**
   * Log warning message.
   * @param {string} message - Warning message
   * @param {Object} [data] - Additional data
   */
  warn(message, data) {
    if (this._shouldLog('warn')) {
      console.warn(this._format('warn', message, data));
    }
  }

  /**
   * Log error message.
   * @param {string} message - Error message
   * @param {Error|Object} [error] - Error object or additional data
   */
  error(message, error) {
    if (this._shouldLog('error')) {
      console.error(this._format('error', message, error));
    }
  }

  /**
   * Log fatal message.
   * @param {string} message - Fatal message
   * @param {Error|Object} [error] - Error object or additional data
   */
  fatal(message, error) {
    if (this._shouldLog('fatal')) {
      console.error(this._format('fatal', message, error));
    }
  }
}

// Create application logger
const logger = new Logger('App', { level: 'info' });

// ---------------------------------------------------------------------------
// Custom Error Classes
// ---------------------------------------------------------------------------

/**
 * Application base error class.
 * @class
 * @extends Error
 */
class AppError extends Error {
  /**
   * @param {string} message - Error message
   * @param {string} [code='UNKNOWN_ERROR'] - Error code
   * @param {Object} [details] - Additional error details
   */
  constructor(message, code = 'UNKNOWN_ERROR', details = {}) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }
}

/**
 * Data validation error.
 * @class
 * @extends AppError
 */
class ValidationError extends AppError {
  /**
   * @param {string} message - Error message
   * @param {Object} [details] - Validation details
   */
  constructor(message, details = {}) {
    super(message, 'VALIDATION_ERROR', details);
    this.name = 'ValidationError';
  }
}

/**
 * Network error.
 * @class
 * @extends AppError
 */
class NetworkError extends AppError {
  /**
   * @param {string} message - Error message
   * @param {Object} [details] - Network details
   */
  constructor(message, details = {}) {
    super(message, 'NETWORK_ERROR', details);
    this.name = 'NetworkError';
  }
}

/**
 * Data parsing error.
 * @class
 * @extends AppError
 */
class ParseError extends AppError {
  /**
   * @param {string} message - Error message
   * @param {Object} [details] - Parsing details
   */
  constructor(message, details = {}) {
    super(message, 'PARSE_ERROR', details);
    this.name = 'ParseError';
  }
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/**
 * Debounce function to limit execution frequency.
 * @param {Function} fn - Function to debounce
 * @param {number} delay - Delay in milliseconds
 * @returns {Function} Debounced function
 */
function debounce(fn, delay) {
  let timeoutId = null;
  return function(...args) {
    const context = this;
    if (timeoutId !== null) {
      clearTimeout(timeoutId);
    }
    timeoutId = setTimeout(() => {
      fn.apply(context, args);
      timeoutId = null;
    }, delay);
  };
}

/**
 * Throttle function to limit execution rate.
 * @param {Function} fn - Function to throttle
 * @param {number} limit - Limit in milliseconds
 * @returns {Function} Throttled function
 */
function throttle(fn, limit) {
  let inThrottle = false;
  let lastFn = null;
  let lastTime = 0;
  
  return function(...args) {
    const context = this;
    const now = Date.now();
    
    if (!inThrottle) {
      fn.apply(context, args);
      lastTime = now;
      inThrottle = true;
    } else {
      clearTimeout(lastFn);
      lastFn = setTimeout(() => {
        if (Date.now() - lastTime >= limit) {
          fn.apply(context, args);
          lastTime = Date.now();
        }
      }, Math.max(0, limit - (now - lastTime)));
    }
  };
}

/**
 * Deep clone an object.
 * @param {Object} obj - Object to clone
 * @returns {Object} Cloned object
 */
function deepClone(obj) {
  try {
    return JSON.parse(JSON.stringify(obj));
  } catch (error) {
    logger.error('Deep clone failed', error);
    return Object.assign({}, obj);
  }
}

/**
 * Sanitize HTML string to prevent XSS.
 * @param {string} str - String to sanitize
 * @returns {string} Sanitized string
 */
function sanitizeHTML(str) {
  if (typeof str !== 'string') return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;'
  };
  const reg = /[&<>"'/]/g;
  return str.replace(reg, (match) => map[match]);
}

/**
 * Validate URL format.
 * @param {string} url - URL to validate
 * @returns {boolean} Whether URL is valid
 */
function isValidURL(url) {
  if (typeof url !== 'string' || url.trim().length === 0) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (error) {
    return false;
  }
}

/**
 * Format date string.
 * @param {string|Date} date - Date to format
 * @param {string} [format='ISO'] - Format type
 * @returns {string} Formatted date string
 */
function formatDate(date, format = 'ISO') {
  try {
    const d = date instanceof Date ? date : new Date(date);
    if (isNaN(d.getTime())) {
      throw new Error('Invalid date');
    }
    
    switch (format) {
      case 'ISO':
        return d.toISOString();
      case 'LOCALE':
        return d.toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        });
      case 'RELATIVE':
        return getRelativeTime(d);
      default:
        return d.toISOString();
    }
  } catch (error) {
    logger.error('Date formatting failed', error);
    return 'Invalid date';
  }
}

/**
 * Get relative time string.
 * @param {Date} date - Date to compare
 * @returns {string} Relative time string
 */
function getRelativeTime(date) {
  const now = new Date();
  const diff = now - date;
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (seconds < 60) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  return formatDate(date, 'LOCALE');
}

/**
 * Generate unique ID.
 * @returns {string} Unique ID
 */
function generateId() {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// ---------------------------------------------------------------------------
// Data Manager
// ---------------------------------------------------------------------------

/**
 * Manages application data with caching and validation.
 * @class
 */
class DataManager {
  /**
   * @param {Object} [options] - Data manager options
   * @param {number} [options.cacheTTL=300000] - Cache TTL in milliseconds
   * @param {number} [options.maxRetries=3] - Maximum retry attempts
   */
  constructor(options = {}) {
    /** @type {Object} */
    this.cache = {};
    /** @type {number} */
    this.cacheTTL = options.cacheTTL || CONFIG.refreshInterval;
    /** @type {number} */
    this.maxRetries = options.maxRetries || CONFIG.maxRetries;
    /** @type {Logger} */
    this.logger = new Logger('DataManager', { level: 'info' });
  }

  /**
   * Fetch data with retry logic.
   * @param {string} url - URL to fetch
   * @param {Object} [options] - Fetch options
   * @returns {Promise<Object>} Fetched data
   */
  async fetchWithRetry(url, options = {}) {
    const cacheKey = `${url}-${JSON.stringify(options)}`;
    
    // Check cache
    if (this.cache[cacheKey] && Date.now() - this.cache[cacheKey].timestamp < this.cacheTTL) {
      this.logger.debug('Cache hit', { url });
      return this.cache[cacheKey].data;
    }
    
    let lastError = null;
    
    for (let attempt