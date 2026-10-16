import { apiClient } from './client'

export const getSummary = () => apiClient.get('/dashboard/summary').then((r) => r.data)

export const getTimeline = () => apiClient.get('/dashboard/timeline').then((r) => r.data)

export const getGraph = (scanJobId) => apiClient.get(`/dashboard/graph/${scanJobId}`).then((r) => r.data)

export const triggerScan = (repoUrl, options = {}) =>
  apiClient
    .post('/scan/repo', {
      repo_url: repoUrl,
      enable_active_validation: options.enableActiveValidation ?? false,
      repo_visibility: options.repoVisibility ?? 'unknown',
    })
    .then((r) => r.data)

export const getScanStatus = (scanJobId) => apiClient.get(`/scan/${scanJobId}`).then((r) => r.data)

export const getScanResults = (scanJobId) => apiClient.get(`/scan/${scanJobId}/results`).then((r) => r.data)

export const clearScanHistory = () => apiClient.delete('/scan').then((r) => r.data)

export const getSecrets = (filters = {}) => apiClient.get('/secrets', { params: filters }).then((r) => r.data)

export const getSecretStats = () => apiClient.get('/secrets/stats').then((r) => r.data)

export const getDevelopers = (filters = {}) =>
  apiClient.get('/developers', { params: filters }).then((r) => r.data)

export const getDeveloper = (email) =>
  apiClient.get(`/developers/${encodeURIComponent(email)}`).then((r) => r.data)

export const getDeveloperReport = (email) =>
  apiClient
    .get(`/developers/${encodeURIComponent(email)}/report`, { responseType: 'text' })
    .then((r) => r.data)

export const checkHealth = () => apiClient.get('/health').then((r) => r.data)
