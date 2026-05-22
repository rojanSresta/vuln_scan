// API Configuration
export const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';
export const API_PREFIX = '/api/v1';

export const API_ENDPOINTS = {
  // Auth endpoints
  AUTH_LOGIN: `${API_PREFIX}/auth/login`,
  AUTH_REGISTER: `${API_PREFIX}/auth/register`,
  AUTH_LOGOUT: `${API_PREFIX}/auth/logout`,
  
  // Scan endpoints
  SCANS_CREATE: `${API_PREFIX}/scans`,
  SCANS_LIST: `${API_PREFIX}/scans`,
  SCANS_GET: (id) => `${API_PREFIX}/scans/${id}`,
  SCANS_CANCEL: (id) => `${API_PREFIX}/scans/${id}/cancel`,
  SCANS_DOWNLOAD: (id) => `${API_PREFIX}/scans/${id}/download`,
  
  // History endpoints
  HISTORY_LIST: `${API_PREFIX}/history`,
  HISTORY_GET: (id) => `${API_PREFIX}/history/${id}`,
  
  // Admin endpoints
  ADMIN_LOGIN: `${API_PREFIX}/admin/login`,
  ADMIN_STATS: `${API_PREFIX}/admin/stats`,
};
