const { execFile } = require('node:child_process');
const dns = require('node:dns').promises;

async function fetchJson(url, timeoutMs = 6000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal, headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function publicIpv4() {
  try {
    const data = await fetchJson('https://api.ipify.org?format=json');
    return typeof data.ip === 'string' ? data.ip : null;
  } catch {
    return null;
  }
}

async function publicIpv6() {
  try {
    const data = await fetchJson('https://api6.ipify.org?format=json', 4000);
    return typeof data.ip === 'string' && data.ip.includes(':') ? data.ip : null;
  } catch {
    return null;
  }
}

async function dnsResolution() {
  try {
    const result = await dns.lookup('discord.com', { family: 4 });
    return { working: Boolean(result?.address), sample: result?.address || null };
  } catch {
    return { working: false, sample: null };
  }
}

function windowsDnsServers() {
  return new Promise(resolve => {
    const script = "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | ForEach-Object { \"$($_.InterfaceAlias): $($_.ServerAddresses -join ', ')\" } | Sort-Object -Unique | ConvertTo-Json -Compress";
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], { windowsHide: true, timeout: 7000 }, (error, stdout) => {
      if (error || !stdout.trim()) return resolve([]);
      try {
        const parsed = JSON.parse(stdout.trim());
        resolve(Array.isArray(parsed) ? parsed : [parsed]);
      } catch {
        resolve([]);
      }
    });
  });
}

async function runDiagnostics() {
  const [ipv4, ipv6, dnsResult, dnsServers] = await Promise.all([
    publicIpv4(), publicIpv6(), dnsResolution(), windowsDnsServers()
  ]);
  return { ipv4, ipv6, dns: dnsResult, dnsServers, checkedAt: Date.now() };
}

module.exports = { runDiagnostics };
