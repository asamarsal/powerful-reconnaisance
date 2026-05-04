import axios from 'axios';
import config from '../../config/default.js';

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
];

function getRandomUA() {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

export function createHttpClient(options = {}) {
  const instance = axios.create({
    timeout: options.timeout || config.timeout,
    maxRedirects: options.followRedirects === false ? 0 : (options.maxRedirects || 5),
    validateStatus: () => true, // Don't throw on any status code
    headers: {
      'User-Agent': options.userAgent || getRandomUA(),
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate',
      'Connection': 'keep-alive',
      ...(options.headers || {}),
    },
    ...(options.proxy ? { proxy: parseProxy(options.proxy) } : {}),
  });

  return instance;
}

function parseProxy(proxyUrl) {
  try {
    const url = new URL(proxyUrl);
    return {
      host: url.hostname,
      port: parseInt(url.port),
      protocol: url.protocol.replace(':', ''),
      ...(url.username ? { auth: { username: url.username, password: url.password } } : {}),
    };
  } catch {
    return null;
  }
}

export async function httpGet(url, options = {}) {
  const client = createHttpClient(options);
  try {
    const response = await client.get(url);
    return {
      status: response.status,
      headers: response.headers,
      data: response.data,
      url: response.config.url,
      redirected: response.request?.res?.responseUrl !== url,
      finalUrl: response.request?.res?.responseUrl || url,
    };
  } catch (error) {
    return { status: 0, headers: {}, data: '', url, error: error.message };
  }
}

export async function httpPost(url, data, options = {}) {
  const client = createHttpClient(options);
  try {
    const response = await client.post(url, data, {
      headers: options.contentType ? { 'Content-Type': options.contentType } : {},
    });
    return {
      status: response.status,
      headers: response.headers,
      data: response.data,
      url: response.config.url,
    };
  } catch (error) {
    return { status: 0, headers: {}, data: '', url, error: error.message };
  }
}

export async function httpRequest(method, url, options = {}) {
  const client = createHttpClient(options);
  try {
    const response = await client.request({
      method,
      url,
      data: options.body,
      headers: options.headers || {},
    });
    return {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
      data: response.data,
      url: response.config.url,
    };
  } catch (error) {
    return { status: 0, headers: {}, data: '', url, error: error.message };
  }
}

export { getRandomUA, USER_AGENTS };
export default { createHttpClient, httpGet, httpPost, httpRequest, getRandomUA };
