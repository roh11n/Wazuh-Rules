import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
export const API = `${BACKEND_URL}/api`;

export const api = axios.create({ baseURL: API });

export const createScan = (payload) => api.post("/scans", payload).then(r => r.data);
export const listScans = () => api.get("/scans").then(r => r.data);
export const getScan = (id) => api.get(`/scans/${id}`).then(r => r.data);
export const getScanStatus = (id) => api.get(`/scans/${id}/status`).then(r => r.data);
export const deleteScan = (id) => api.delete(`/scans/${id}`).then(r => r.data);
export const getSettings = () => api.get("/settings").then(r => r.data);
export const updateSettings = (payload) => api.put("/settings", payload).then(r => r.data);
export const reportUrl = (id) => `${API}/scans/${id}/report`;
