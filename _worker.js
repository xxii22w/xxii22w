var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// _worker.js
var epd = true;
var epi = true;
var egi = true;
var ev = true;
var scu = "https://url.v1.mk/sub";
var directDomains = [
  { name: "cloudflare.182682.xyz", domain: "cloudflare.182682.xyz" },
  { domain: "freeyx.cloudflare88.eu.org" },
  { domain: "bestcf.top" },
  { domain: "cdn.2020111.xyz" },
  { domain: "cf.0sm.com" },
  { domain: "cf.090227.xyz" },
  { domain: "cf.zhetengsha.eu.org" },
  { domain: "cfip.1323123.xyz" },
  { domain: "cloudflare-ip.mofashi.ltd" },
  { domain: "cf.877771.xyz" },
  { domain: "xn--b6gac.eu.org" }
];
var defaultIPURL = "https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt";
function isValidUUID(str) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(str);
}
__name(isValidUUID, "isValidUUID");
async function fetchDynamicIPs(ipv4Enabled = true, ipv6Enabled = true, ispMobile = true, ispUnicom = true, ispTelecom = true) {
  const v4Url = "https://www.wetest.vip/page/cloudflare/address_v4.html";
  const v6Url = "https://www.wetest.vip/page/cloudflare/address_v6.html";
  let results = [];
  try {
    const fetchPromises = [];
    if (ipv4Enabled) {
      fetchPromises.push(fetchAndParseWetest(v4Url));
    } else {
      fetchPromises.push(Promise.resolve([]));
    }
    if (ipv6Enabled) {
      fetchPromises.push(fetchAndParseWetest(v6Url));
    } else {
      fetchPromises.push(Promise.resolve([]));
    }
    const [ipv4List, ipv6List] = await Promise.all(fetchPromises);
    results = [...ipv4List, ...ipv6List];
    if (results.length > 0) {
      results = results.filter((item) => {
        const isp = item.isp || "";
        if (isp.includes("\u79FB\u52A8") && !ispMobile) return false;
        if (isp.includes("\u8054\u901A") && !ispUnicom) return false;
        if (isp.includes("\u7535\u4FE1") && !ispTelecom) return false;
        return true;
      });
    }
    return results.length > 0 ? results : [];
  } catch (e) {
    return [];
  }
}
__name(fetchDynamicIPs, "fetchDynamicIPs");
async function fetchAndParseWetest(url) {
  try {
    const response = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0" } });
    if (!response.ok) return [];
    const html = await response.text();
    const results = [];
    const rowRegex = /<tr[\s\S]*?<\/tr>/g;
    const cellRegex = /<td data-label="线路名称">(.+?)<\/td>[\s\S]*?<td data-label="优选地址">([\d.:a-fA-F]+)<\/td>[\s\S]*?<td data-label="数据中心">(.+?)<\/td>/;
    let match;
    while ((match = rowRegex.exec(html)) !== null) {
      const rowHtml = match[0];
      const cellMatch = rowHtml.match(cellRegex);
      if (cellMatch && cellMatch[1] && cellMatch[2]) {
        const colo = cellMatch[3] ? cellMatch[3].trim().replace(/<.*?>/g, "") : "";
        results.push({
          isp: cellMatch[1].trim().replace(/<.*?>/g, ""),
          ip: cellMatch[2].trim(),
          colo
        });
      }
    }
    return results;
  } catch (error) {
    return [];
  }
}
__name(fetchAndParseWetest, "fetchAndParseWetest");
async function \u6574\u7406\u6210\u6570\u7EC4(\u5185\u5BB9) {
  var \u66FF\u6362\u540E\u7684\u5185\u5BB9 = \u5185\u5BB9.replace(/[	"'\r\n]+/g, ",").replace(/,+/g, ",");
  if (\u66FF\u6362\u540E\u7684\u5185\u5BB9.charAt(0) == ",") \u66FF\u6362\u540E\u7684\u5185\u5BB9 = \u66FF\u6362\u540E\u7684\u5185\u5BB9.slice(1);
  if (\u66FF\u6362\u540E\u7684\u5185\u5BB9.charAt(\u66FF\u6362\u540E\u7684\u5185\u5BB9.length - 1) == ",") \u66FF\u6362\u540E\u7684\u5185\u5BB9 = \u66FF\u6362\u540E\u7684\u5185\u5BB9.slice(0, \u66FF\u6362\u540E\u7684\u5185\u5BB9.length - 1);
  const \u5730\u5740\u6570\u7EC4 = \u66FF\u6362\u540E\u7684\u5185\u5BB9.split(",");
  return \u5730\u5740\u6570\u7EC4;
}
__name(\u6574\u7406\u6210\u6570\u7EC4, "\u6574\u7406\u6210\u6570\u7EC4");
async function \u8BF7\u6C42\u4F18\u9009API(urls, \u9ED8\u8BA4\u7AEF\u53E3 = "443", \u8D85\u65F6\u65F6\u95F4 = 3e3) {
  if (!urls?.length) return [];
  const results = /* @__PURE__ */ new Set();
  await Promise.allSettled(urls.map(async (url) => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), \u8D85\u65F6\u65F6\u95F4);
      const response = await fetch(url, { signal: controller.signal });
      clearTimeout(timeoutId);
      let text = "";
      try {
        const buffer = await response.arrayBuffer();
        const contentType = (response.headers.get("content-type") || "").toLowerCase();
        const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || "";
        let decoders = ["utf-8", "gb2312"];
        if (charset.includes("gb") || charset.includes("gbk") || charset.includes("gb2312")) {
          decoders = ["gb2312", "utf-8"];
        }
        let decodeSuccess = false;
        for (const decoder of decoders) {
          try {
            const decoded = new TextDecoder(decoder).decode(buffer);
            if (decoded && decoded.length > 0 && !decoded.includes("\uFFFD")) {
              text = decoded;
              decodeSuccess = true;
              break;
            } else if (decoded && decoded.length > 0) {
              continue;
            }
          } catch (e) {
            continue;
          }
        }
        if (!decodeSuccess) {
          text = await response.text();
        }
        if (!text || text.trim().length === 0) {
          return;
        }
      } catch (e) {
        console.error("Failed to decode response:", e);
        return;
      }
      const lines = text.trim().split("\n").map((l) => l.trim()).filter((l) => l);
      const isCSV = lines.length > 1 && lines[0].includes(",");
      const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
      if (!isCSV) {
        lines.forEach((line) => {
          const hashIndex = line.indexOf("#");
          const [hostPart, remark] = hashIndex > -1 ? [line.substring(0, hashIndex), line.substring(hashIndex)] : [line, ""];
          let hasPort = false;
          if (hostPart.startsWith("[")) {
            hasPort = /\]:(\d+)$/.test(hostPart);
          } else {
            const colonIndex = hostPart.lastIndexOf(":");
            hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
          }
          const port = new URL(url).searchParams.get("port") || \u9ED8\u8BA4\u7AEF\u53E3;
          results.add(hasPort ? line : `${hostPart}:${port}${remark}`);
        });
      } else {
        const headers = lines[0].split(",").map((h) => h.trim());
        const dataLines = lines.slice(1);
        if (headers.includes("IP\u5730\u5740") && headers.includes("\u7AEF\u53E3") && headers.includes("\u6570\u636E\u4E2D\u5FC3")) {
          const ipIdx = headers.indexOf("IP\u5730\u5740"), portIdx = headers.indexOf("\u7AEF\u53E3");
          const remarkIdx = headers.indexOf("\u56FD\u5BB6") > -1 ? headers.indexOf("\u56FD\u5BB6") : headers.indexOf("\u57CE\u5E02") > -1 ? headers.indexOf("\u57CE\u5E02") : headers.indexOf("\u6570\u636E\u4E2D\u5FC3");
          const tlsIdx = headers.indexOf("TLS");
          dataLines.forEach((line) => {
            const cols = line.split(",").map((c) => c.trim());
            if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== "true") return;
            const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
            results.add(`${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`);
          });
        } else if (headers.some((h) => h.includes("IP")) && headers.some((h) => h.includes("\u5EF6\u8FDF")) && headers.some((h) => h.includes("\u4E0B\u8F7D\u901F\u5EA6"))) {
          const ipIdx = headers.findIndex((h) => h.includes("IP"));
          const delayIdx = headers.findIndex((h) => h.includes("\u5EF6\u8FDF"));
          const speedIdx = headers.findIndex((h) => h.includes("\u4E0B\u8F7D\u901F\u5EA6"));
          const port = new URL(url).searchParams.get("port") || \u9ED8\u8BA4\u7AEF\u53E3;
          dataLines.forEach((line) => {
            const cols = line.split(",").map((c) => c.trim());
            const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
            results.add(`${wrappedIP}:${port}#CF\u4F18\u9009 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`);
          });
        }
      }
    } catch (e) {
    }
  }));
  return Array.from(results);
}
__name(\u8BF7\u6C42\u4F18\u9009API, "\u8BF7\u6C42\u4F18\u9009API");
async function fetchAndParseNewIPs(piu) {
  const url = piu || defaultIPURL;
  try {
    const response = await fetch(url);
    if (!response.ok) return [];
    const text = await response.text();
    const results = [];
    const lines = text.trim().replace(/\r/g, "").split("\n");
    const regex = /^([^:]+):(\d+)#(.*)$/;
    for (const line of lines) {
      const trimmedLine = line.trim();
      if (!trimmedLine) continue;
      const match = trimmedLine.match(regex);
      if (match) {
        results.push({
          ip: match[1],
          port: parseInt(match[2], 10),
          name: match[3].trim() || match[1]
        });
      }
    }
    return results;
  } catch (error) {
    return [];
  }
}
__name(fetchAndParseNewIPs, "fetchAndParseNewIPs");
function generateLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = "/") {
  const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
  const defaultHttpsPorts = [443];
  const defaultHttpPorts = disableNonTLS ? [] : [80];
  const links = [];
  const wsPath = customPath || "/";
  const proto = "vless";
  list.forEach((item) => {
    let nodeNameBase = item.isp ? item.isp.replace(/\s/g, "_") : item.name || item.domain || item.ip;
    if (item.colo && item.colo.trim()) {
      nodeNameBase = `${nodeNameBase}-${item.colo.trim()}`;
    }
    const safeIP = item.ip.includes(":") ? `[${item.ip}]` : item.ip;
    let portsToGenerate = [];
    if (item.port) {
      const port = item.port;
      if (CF_HTTPS_PORTS.includes(port)) {
        portsToGenerate.push({ port, tls: true });
      } else if (CF_HTTP_PORTS.includes(port)) {
        portsToGenerate.push({ port, tls: false });
      } else {
        portsToGenerate.push({ port, tls: true });
      }
    } else {
      defaultHttpsPorts.forEach((port) => {
        portsToGenerate.push({ port, tls: true });
      });
      defaultHttpPorts.forEach((port) => {
        portsToGenerate.push({ port, tls: false });
      });
    }
    portsToGenerate.forEach(({ port, tls }) => {
      if (tls) {
        const wsNodeName = `${nodeNameBase}-${port}-WS-TLS`;
        const wsParams = new URLSearchParams({
          encryption: "none",
          security: "tls",
          sni: workerDomain,
          fp: "chrome",
          type: "ws",
          host: workerDomain,
          path: wsPath
        });
        links.push(`${proto}://${user}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
      } else {
        const wsNodeName = `${nodeNameBase}-${port}-WS`;
        const wsParams = new URLSearchParams({
          encryption: "none",
          security: "none",
          type: "ws",
          host: workerDomain,
          path: wsPath
        });
        links.push(`${proto}://${user}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
      }
    });
  });
  return links;
}
__name(generateLinksFromSource, "generateLinksFromSource");
async function generateTrojanLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = "/") {
  const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
  const defaultHttpsPorts = [443];
  const defaultHttpPorts = disableNonTLS ? [] : [80];
  const links = [];
  const wsPath = customPath || "/";
  const password = user;
  list.forEach((item) => {
    let nodeNameBase = item.isp ? item.isp.replace(/\s/g, "_") : item.name || item.domain || item.ip;
    if (item.colo && item.colo.trim()) {
      nodeNameBase = `${nodeNameBase}-${item.colo.trim()}`;
    }
    const safeIP = item.ip.includes(":") ? `[${item.ip}]` : item.ip;
    let portsToGenerate = [];
    if (item.port) {
      const port = item.port;
      if (CF_HTTPS_PORTS.includes(port)) {
        portsToGenerate.push({ port, tls: true });
      } else if (CF_HTTP_PORTS.includes(port)) {
        if (!disableNonTLS) {
          portsToGenerate.push({ port, tls: false });
        }
      } else {
        portsToGenerate.push({ port, tls: true });
      }
    } else {
      defaultHttpsPorts.forEach((port) => {
        portsToGenerate.push({ port, tls: true });
      });
      defaultHttpPorts.forEach((port) => {
        portsToGenerate.push({ port, tls: false });
      });
    }
    portsToGenerate.forEach(({ port, tls }) => {
      if (tls) {
        const wsNodeName = `${nodeNameBase}-${port}-Trojan-WS-TLS`;
        const wsParams = new URLSearchParams({
          security: "tls",
          sni: workerDomain,
          fp: "chrome",
          type: "ws",
          host: workerDomain,
          path: wsPath
        });
        links.push(`trojan://${password}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
      } else {
        const wsNodeName = `${nodeNameBase}-${port}-Trojan-WS`;
        const wsParams = new URLSearchParams({
          security: "none",
          type: "ws",
          host: workerDomain,
          path: wsPath
        });
        links.push(`trojan://${password}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
      }
    });
  });
  return links;
}
__name(generateTrojanLinksFromSource, "generateTrojanLinksFromSource");
function generateVMessLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = "/") {
  const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
  const defaultHttpsPorts = [443];
  const defaultHttpPorts = disableNonTLS ? [] : [80];
  const links = [];
  const wsPath = customPath || "/";
  list.forEach((item) => {
    let nodeNameBase = item.isp ? item.isp.replace(/\s/g, "_") : item.name || item.domain || item.ip;
    if (item.colo && item.colo.trim()) {
      nodeNameBase = `${nodeNameBase}-${item.colo.trim()}`;
    }
    const safeIP = item.ip.includes(":") ? `[${item.ip}]` : item.ip;
    let portsToGenerate = [];
    if (item.port) {
      const port = item.port;
      if (CF_HTTPS_PORTS.includes(port)) {
        portsToGenerate.push({ port, tls: true });
      } else if (CF_HTTP_PORTS.includes(port)) {
        if (!disableNonTLS) {
          portsToGenerate.push({ port, tls: false });
        }
      } else {
        portsToGenerate.push({ port, tls: true });
      }
    } else {
      defaultHttpsPorts.forEach((port) => {
        portsToGenerate.push({ port, tls: true });
      });
      defaultHttpPorts.forEach((port) => {
        portsToGenerate.push({ port, tls: false });
      });
    }
    portsToGenerate.forEach(({ port, tls }) => {
      const vmessConfig = {
        v: "2",
        ps: tls ? `${nodeNameBase}-${port}-VMess-WS-TLS` : `${nodeNameBase}-${port}-VMess-WS`,
        add: safeIP,
        port: port.toString(),
        id: user,
        aid: "0",
        scy: "auto",
        net: "ws",
        type: "none",
        host: workerDomain,
        path: wsPath,
        tls: tls ? "tls" : "none"
      };
      if (tls) {
        vmessConfig.sni = workerDomain;
        vmessConfig.fp = "chrome";
      }
      const vmessBase64 = btoa(JSON.stringify(vmessConfig));
      links.push(`vmess://${vmessBase64}`);
    });
  });
  return links;
}
__name(generateVMessLinksFromSource, "generateVMessLinksFromSource");
function generateLinksFromNewIPs(list, user, workerDomain, customPath = "/") {
  const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
  const links = [];
  const wsPath = customPath || "/";
  const proto = "vless";
  list.forEach((item) => {
    const nodeName = item.name.replace(/\s/g, "_");
    const port = item.port;
    if (CF_HTTPS_PORTS.includes(port)) {
      const wsNodeName = `${nodeName}-${port}-WS-TLS`;
      const link = `${proto}://${user}@${item.ip}:${port}?encryption=none&security=tls&sni=${workerDomain}&fp=chrome&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
      links.push(link);
    } else if (CF_HTTP_PORTS.includes(port)) {
      const wsNodeName = `${nodeName}-${port}-WS`;
      const link = `${proto}://${user}@${item.ip}:${port}?encryption=none&security=none&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
      links.push(link);
    } else {
      const wsNodeName = `${nodeName}-${port}-WS-TLS`;
      const link = `${proto}://${user}@${item.ip}:${port}?encryption=none&security=tls&sni=${workerDomain}&fp=chrome&type=ws&host=${workerDomain}&path=${wsPath}#${encodeURIComponent(wsNodeName)}`;
      links.push(link);
    }
  });
  return links;
}
__name(generateLinksFromNewIPs, "generateLinksFromNewIPs");
async function handleSubscriptionRequest(request, user, customDomain, piu, ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom, evEnabled, etEnabled, vmEnabled, disableNonTLS, customPath) {
  const url = new URL(request.url);
  const finalLinks = [];
  const workerDomain = url.hostname;
  const nodeDomain = customDomain || url.hostname;
  const target = url.searchParams.get("target") || "base64";
  const wsPath = customPath || "/";
  async function addNodesFromList(list) {
    const hasProtocol = evEnabled || etEnabled || vmEnabled;
    const useVL = hasProtocol ? evEnabled : true;
    if (useVL) {
      finalLinks.push(...generateLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath));
    }
    if (etEnabled) {
      finalLinks.push(...await generateTrojanLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath));
    }
    if (vmEnabled) {
      finalLinks.push(...generateVMessLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath));
    }
  }
  __name(addNodesFromList, "addNodesFromList");
  const nativeList = [{ ip: workerDomain, isp: "\u539F\u751F\u5730\u5740" }];
  await addNodesFromList(nativeList);
  if (epd) {
    const domainList = directDomains.map((d) => ({ ip: d.domain, isp: d.name || d.domain }));
    await addNodesFromList(domainList);
  }
  if (epi) {
    try {
      const dynamicIPList = await fetchDynamicIPs(ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom);
      if (dynamicIPList.length > 0) {
        await addNodesFromList(dynamicIPList);
      }
    } catch (error) {
      console.error("\u83B7\u53D6\u52A8\u6001IP\u5931\u8D25:", error);
    }
  }
  if (egi) {
    try {
      if (piu && piu.toLowerCase().startsWith("https://")) {
        const \u4F18\u9009API\u7684IP = await \u8BF7\u6C42\u4F18\u9009API([piu]);
        if (\u4F18\u9009API\u7684IP && \u4F18\u9009API\u7684IP.length > 0) {
          const IP\u5217\u8868 = \u4F18\u9009API\u7684IP.map((\u539F\u59CB\u5730\u5740) => {
            const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
            const match = \u539F\u59CB\u5730\u5740.match(regex);
            if (match) {
              const \u8282\u70B9\u5730\u5740 = match[1].replace(/[\[\]]/g, "");
              const \u8282\u70B9\u7AEF\u53E3 = match[2] || 443;
              const \u8282\u70B9\u5907\u6CE8 = match[3] || \u8282\u70B9\u5730\u5740;
              return {
                ip: \u8282\u70B9\u5730\u5740,
                port: parseInt(\u8282\u70B9\u7AEF\u53E3),
                name: \u8282\u70B9\u5907\u6CE8
              };
            }
            return null;
          }).filter((item) => item !== null);
          if (IP\u5217\u8868.length > 0) {
            const hasProtocol = evEnabled || etEnabled || vmEnabled;
            const useVL = hasProtocol ? evEnabled : true;
            if (useVL) {
              finalLinks.push(...generateLinksFromNewIPs(IP\u5217\u8868, user, nodeDomain, wsPath));
            }
          }
        }
      } else if (piu && piu.includes("\n")) {
        const \u5B8C\u6574\u4F18\u9009\u5217\u8868 = await \u6574\u7406\u6210\u6570\u7EC4(piu);
        const \u4F18\u9009API = [], \u4F18\u9009IP = [], \u5176\u4ED6\u8282\u70B9 = [];
        for (const \u5143\u7D20 of \u5B8C\u6574\u4F18\u9009\u5217\u8868) {
          if (\u5143\u7D20.toLowerCase().startsWith("https://")) {
            \u4F18\u9009API.push(\u5143\u7D20);
          } else if (\u5143\u7D20.toLowerCase().includes("://")) {
            \u5176\u4ED6\u8282\u70B9.push(\u5143\u7D20);
          } else {
            \u4F18\u9009IP.push(\u5143\u7D20);
          }
        }
        if (\u4F18\u9009API.length > 0) {
          const \u4F18\u9009API\u7684IP = await \u8BF7\u6C42\u4F18\u9009API(\u4F18\u9009API);
          \u4F18\u9009IP.push(...\u4F18\u9009API\u7684IP);
        }
        if (\u4F18\u9009IP.length > 0) {
          const IP\u5217\u8868 = \u4F18\u9009IP.map((\u539F\u59CB\u5730\u5740) => {
            const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
            const match = \u539F\u59CB\u5730\u5740.match(regex);
            if (match) {
              const \u8282\u70B9\u5730\u5740 = match[1].replace(/[\[\]]/g, "");
              const \u8282\u70B9\u7AEF\u53E3 = match[2] || 443;
              const \u8282\u70B9\u5907\u6CE8 = match[3] || \u8282\u70B9\u5730\u5740;
              return {
                ip: \u8282\u70B9\u5730\u5740,
                port: parseInt(\u8282\u70B9\u7AEF\u53E3),
                name: \u8282\u70B9\u5907\u6CE8
              };
            }
            return null;
          }).filter((item) => item !== null);
          if (IP\u5217\u8868.length > 0) {
            const hasProtocol = evEnabled || etEnabled || vmEnabled;
            const useVL = hasProtocol ? evEnabled : true;
            if (useVL) {
              finalLinks.push(...generateLinksFromNewIPs(IP\u5217\u8868, user, nodeDomain, wsPath));
            }
          }
        }
      } else {
        const newIPList = await fetchAndParseNewIPs(piu);
        if (newIPList.length > 0) {
          const hasProtocol = evEnabled || etEnabled || vmEnabled;
          const useVL = hasProtocol ? evEnabled : true;
          if (useVL) {
            finalLinks.push(...generateLinksFromNewIPs(newIPList, user, nodeDomain, wsPath));
          }
        }
      }
    } catch (error) {
      console.error("\u83B7\u53D6\u4F18\u9009IP\u5931\u8D25:", error);
    }
  }
  if (finalLinks.length === 0) {
    const errorRemark = "\u6240\u6709\u8282\u70B9\u83B7\u53D6\u5931\u8D25";
    const errorLink = `vless://00000000-0000-0000-0000-000000000000@127.0.0.1:80?encryption=none&security=none&type=ws&host=error.com&path=%2F#${encodeURIComponent(errorRemark)}`;
    finalLinks.push(errorLink);
  }
  let subscriptionContent;
  let contentType = "text/plain; charset=utf-8";
  switch (target.toLowerCase()) {
    case "clash":
    case "clashr":
      subscriptionContent = generateClashConfig(finalLinks);
      contentType = "text/yaml; charset=utf-8";
      break;
    case "surge":
    case "surge2":
    case "surge3":
    case "surge4":
      subscriptionContent = generateSurgeConfig(finalLinks);
      break;
    case "quantumult":
    case "quanx":
      subscriptionContent = generateQuantumultConfig(finalLinks);
      break;
    default:
      subscriptionContent = btoa(finalLinks.join("\n"));
  }
  return new Response(subscriptionContent, {
    headers: {
      "Content-Type": contentType,
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
    }
  });
}
__name(handleSubscriptionRequest, "handleSubscriptionRequest");
function generateClashConfig(links) {
  let yaml = "port: 7890\n";
  yaml += "socks-port: 7891\n";
  yaml += "allow-lan: false\n";
  yaml += "mode: rule\n";
  yaml += "log-level: info\n\n";
  yaml += "proxies:\n";
  const proxyNames = [];
  links.forEach((link, index) => {
    const name = decodeURIComponent(link.split("#")[1] || `\u8282\u70B9${index + 1}`);
    proxyNames.push(name);
    const server = link.match(/@([^:]+):(\d+)/)?.[1] || "";
    const port = link.match(/@[^:]+:(\d+)/)?.[1] || "443";
    const uuid = link.match(/vless:\/\/([^@]+)@/)?.[1] || "";
    const tls = link.includes("security=tls");
    const path = link.match(/path=([^&#]+)/)?.[1] || "/";
    const host = link.match(/host=([^&#]+)/)?.[1] || "";
    const sni = link.match(/sni=([^&#]+)/)?.[1] || "";
    yaml += `  - name: ${name}
`;
    yaml += `    type: vless
`;
    yaml += `    server: ${server}
`;
    yaml += `    port: ${port}
`;
    yaml += `    uuid: ${uuid}
`;
    yaml += `    tls: ${tls}
`;
    yaml += `    network: ws
`;
    yaml += `    ws-opts:
`;
    yaml += `      path: ${path}
`;
    yaml += `      headers:
`;
    yaml += `        Host: ${host}
`;
    if (sni) {
      yaml += `    servername: ${sni}
`;
    }
  });
  yaml += "\nproxy-groups:\n";
  yaml += "  - name: PROXY\n";
  yaml += "    type: select\n";
  yaml += `    proxies: [${proxyNames.map((n) => `'${n}'`).join(", ")}]
`;
  yaml += "\nrules:\n";
  yaml += "  - DOMAIN-SUFFIX,local,DIRECT\n";
  yaml += "  - IP-CIDR,127.0.0.0/8,DIRECT\n";
  yaml += "  - GEOIP,CN,DIRECT\n";
  yaml += "  - MATCH,PROXY\n";
  return yaml;
}
__name(generateClashConfig, "generateClashConfig");
function generateSurgeConfig(links) {
  let config = "[Proxy]\n";
  links.forEach((link) => {
    const name = decodeURIComponent(link.split("#")[1] || "\u8282\u70B9");
    config += `${name} = vless, ${link.match(/@([^:]+):(\d+)/)?.[1] || ""}, ${link.match(/@[^:]+:(\d+)/)?.[1] || "443"}, username=${link.match(/vless:\/\/([^@]+)@/)?.[1] || ""}, tls=${link.includes("security=tls")}, ws=true, ws-path=${link.match(/path=([^&#]+)/)?.[1] || "/"}, ws-headers=Host:${link.match(/host=([^&#]+)/)?.[1] || ""}
`;
  });
  config += "\n[Proxy Group]\nPROXY = select, " + links.map((_, i) => decodeURIComponent(links[i].split("#")[1] || `\u8282\u70B9${i + 1}`)).join(", ") + "\n";
  return config;
}
__name(generateSurgeConfig, "generateSurgeConfig");
function generateQuantumultConfig(links) {
  return btoa(links.join("\n"));
}
__name(generateQuantumultConfig, "generateQuantumultConfig");
async function testLatency(host, port = 443, timeout = 5e3) {
  const startTime = Date.now();
  try {
    let testHost = host;
    let testPort = port;
    if (host.includes(":")) {
      const parts = host.split(":");
      testHost = parts[0].replace(/[\[\]]/g, "");
      testPort = parseInt(parts[1]) || port;
    }
    const protocol = testPort === 443 || testPort === 8443 ? "https" : "http";
    const testUrl = `${protocol}://${testHost}:${testPort}/cdn-cgi/trace`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(testUrl, {
        signal: controller.signal,
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
      });
      clearTimeout(timeoutId);
      const responseTime = Date.now() - startTime;
      if (response.ok) {
        const text = await response.text();
        const ipMatch = text.match(/ip=([^\s]+)/);
        const locMatch = text.match(/loc=([^\s]+)/);
        const coloMatch = text.match(/colo=([^\s]+)/);
        return {
          success: true,
          host,
          port: testPort,
          latency: responseTime,
          ip: ipMatch ? ipMatch[1] : null,
          location: locMatch ? locMatch[1] : null,
          colo: coloMatch ? coloMatch[1] : null
        };
      } else {
        return {
          success: false,
          host,
          port: testPort,
          latency: responseTime,
          error: `HTTP ${response.status}`
        };
      }
    } catch (fetchError) {
      clearTimeout(timeoutId);
      const responseTime = Date.now() - startTime;
      if (fetchError.name === "AbortError") {
        return {
          success: false,
          host,
          port: testPort,
          latency: timeout,
          error: "\u8BF7\u6C42\u8D85\u65F6"
        };
      }
      return {
        success: false,
        host,
        port: testPort,
        latency: responseTime,
        error: fetchError.message || "\u8FDE\u63A5\u5931\u8D25"
      };
    }
  } catch (error) {
    const responseTime = Date.now() - startTime;
    return {
      success: false,
      host,
      port,
      latency: responseTime,
      error: error.message || "\u672A\u77E5\u9519\u8BEF"
    };
  }
}
__name(testLatency, "testLatency");
async function batchTestLatency(hosts, port = 443, timeout = 5e3, concurrency = 5) {
  const results = [];
  const chunks = [];
  for (let i = 0; i < hosts.length; i += concurrency) {
    chunks.push(hosts.slice(i, i + concurrency));
  }
  for (const chunk of chunks) {
    const chunkResults = await Promise.allSettled(
      chunk.map((host) => testLatency(host, port, timeout))
    );
    chunkResults.forEach((result, index) => {
      if (result.status === "fulfilled") {
        results.push(result.value);
      } else {
        results.push({
          success: false,
          host: chunk[index],
          port,
          latency: timeout,
          error: result.reason?.message || "\u6D4B\u8BD5\u5931\u8D25"
        });
      }
    });
  }
  results.sort((a, b) => {
    if (a.success && !b.success) return -1;
    if (!a.success && b.success) return 1;
    return a.latency - b.latency;
  });
  return results;
}
__name(batchTestLatency, "batchTestLatency");
function generateHomePage(scuValue) {
  const scu2 = scuValue || "https://url.v1.mk/sub";
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>\u670D\u52A1\u5668\u4F18\u9009\u5DE5\u5177</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(180deg, #f5f5f7 0%, #ffffff 100%);
            color: #1d1d1f;
            min-height: 100vh;
            padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
            overflow-x: hidden;
        }
        
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            padding: 40px 20px 30px;
        }
        
        .header h1 {
            font-size: 34px;
            font-weight: 700;
            letter-spacing: -0.5px;
            color: #1d1d1f;
            margin-bottom: 8px;
        }
        
        .header p {
            font-size: 17px;
            color: #86868b;
            font-weight: 400;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.8);
            backdrop-filter: blur(20px) saturate(180%);
            -webkit-backdrop-filter: blur(20px) saturate(180%);
            border-radius: 20px;
            padding: 24px;
            margin-bottom: 16px;
            box-shadow: 0 2px 16px rgba(0, 0, 0, 0.08);
            border: 0.5px solid rgba(0, 0, 0, 0.04);
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: #86868b;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            font-size: 17px;
            font-weight: 400;
            color: #1d1d1f;
            background: rgba(142, 142, 147, 0.12);
            border: none;
            border-radius: 12px;
            outline: none;
            transition: all 0.2s ease;
            -webkit-appearance: none;
        }
        
        .form-group input:focus {
            background: rgba(142, 142, 147, 0.16);
            transform: scale(1.01);
        }
        
        .form-group input::placeholder {
            color: #86868b;
        }
        
        .switch-group {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 0;
        }
        
        .switch-group label {
            font-size: 17px;
            font-weight: 400;
            color: #1d1d1f;
            text-transform: none;
            letter-spacing: 0;
        }
        
        .switch {
            position: relative;
            width: 51px;
            height: 31px;
            background: rgba(142, 142, 147, 0.3);
            border-radius: 16px;
            transition: background 0.3s ease;
            cursor: pointer;
        }
        
        .switch.active {
            background: #34c759;
        }
        
        .switch::after {
            content: '';
            position: absolute;
            top: 2px;
            left: 2px;
            width: 27px;
            height: 27px;
            background: #ffffff;
            border-radius: 50%;
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }
        
        .switch.active::after {
            transform: translateX(20px);
        }
        
        .btn {
            width: 100%;
            padding: 16px;
            font-size: 17px;
            font-weight: 600;
            color: #ffffff;
            background: #007aff;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.2s ease;
            margin-top: 8px;
            -webkit-appearance: none;
            box-shadow: 0 2px 8px rgba(0, 122, 255, 0.3);
        }
        
        .btn:active {
            transform: scale(0.98);
            opacity: 0.8;
        }
        
        .btn-secondary {
            background: rgba(142, 142, 147, 0.12);
            color: #007aff;
            box-shadow: none;
        }
        
        .btn-secondary:active {
            background: rgba(142, 142, 147, 0.2);
        }
        
        .result {
            margin-top: 20px;
            padding: 16px;
            background: rgba(142, 142, 147, 0.12);
            border-radius: 12px;
            font-size: 15px;
            color: #1d1d1f;
            word-break: break-all;
            display: none;
        }
        
        .result.show {
            display: block;
        }
        
        .result-url {
            margin-top: 12px;
            padding: 12px;
            background: rgba(0, 122, 255, 0.1);
            border-radius: 8px;
            font-size: 13px;
            color: #007aff;
            word-break: break-all;
        }
        
        .copy-btn {
            margin-top: 8px;
            padding: 10px 16px;
            font-size: 15px;
            background: rgba(0, 122, 255, 0.1);
            color: #007aff;
            border: none;
            border-radius: 8px;
            cursor: pointer;
        }
        
        .client-btn {
            padding: 12px 10px;
            font-size: 14px;
            font-weight: 500;
            color: #007aff;
            background: rgba(0, 122, 255, 0.1);
            border: 1px solid rgba(0, 122, 255, 0.2);
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.2s ease;
            -webkit-appearance: none;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            min-width: 0;
        }
        
        .client-btn:active {
            transform: scale(0.98);
            background: rgba(0, 122, 255, 0.2);
        }
        
        .checkbox-label {
            display: flex;
            align-items: center;
            cursor: pointer;
            font-size: 17px;
            font-weight: 400;
            user-select: none;
            -webkit-user-select: none;
            position: relative;
            z-index: 1;
        }
        
        .checkbox-label input[type="checkbox"] {
            margin-right: 8px;
            width: 20px;
            height: 20px;
            cursor: pointer;
            flex-shrink: 0;
            position: relative;
            z-index: 2;
            -webkit-appearance: checkbox;
            appearance: checkbox;
        }
        
        .checkbox-label span {
            cursor: pointer;
            position: relative;
            z-index: 1;
        }
        
        @media (max-width: 480px) {
            .client-btn {
                font-size: 12px;
                padding: 10px 8px;
            }
        }
        
        .footer {
            text-align: center;
            padding: 30px 20px;
            color: #86868b;
            font-size: 13px;
        }
        
        .footer a {
            transition: opacity 0.2s ease;
        }
        
        .footer a:active {
            opacity: 0.6;
        }
        
        @media (prefers-color-scheme: dark) {
            body {
                background: linear-gradient(180deg, #000000 0%, #1c1c1e 100%);
                color: #f5f5f7;
            }
            
            .card {
                background: rgba(28, 28, 30, 0.8);
                border: 0.5px solid rgba(255, 255, 255, 0.1);
            }
            
            .form-group input {
                background: rgba(142, 142, 147, 0.2);
                color: #f5f5f7;
            }
            
            .form-group input:focus {
                background: rgba(142, 142, 147, 0.25);
            }
            
            .switch-group label {
                color: #f5f5f7;
            }
            
            .result {
                background: rgba(142, 142, 147, 0.2);
                color: #f5f5f7;
            }
            
            select {
                background: rgba(142, 142, 147, 0.2) !important;
                color: #f5f5f7 !important;
            }
            
            label span {
                color: #f5f5f7;
            }
            
            .client-btn {
                background: rgba(0, 122, 255, 0.15) !important;
                border-color: rgba(0, 122, 255, 0.3) !important;
                color: #5ac8fa !important;
            }
            
            .footer a {
                color: #5ac8fa !important;
            }
            
            textarea {
                background: rgba(142, 142, 147, 0.2) !important;
                color: #f5f5f7 !important;
            }
            
            textarea::placeholder {
                color: #86868b !important;
            }
            
            #testResult, #batchTestResult {
                color: #f5f5f7 !important;
            }
            
            #testResult div, #batchTestResult div {
                color: #f5f5f7 !important;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>\u670D\u52A1\u5668\u4F18\u9009\u5DE5\u5177</h1>
            <p>\u667A\u80FD\u4F18\u9009 \u2022 \u4E00\u952E\u751F\u6210</p>
        </div>
        
        <div class="card">
            <div class="form-group">
                <label>\u57DF\u540D</label>
                <input type="text" id="domain" placeholder="\u8BF7\u8F93\u5165\u60A8\u7684\u57DF\u540D">
            </div>
            
            <div class="form-group">
                <label>UUID</label>
                <input type="text" id="uuid" placeholder="\u8BF7\u8F93\u5165UUID">
            </div>
            
            <div class="form-group">
                <label>WebSocket\u8DEF\u5F84\uFF08\u53EF\u9009\uFF09</label>
                <input type="text" id="customPath" placeholder="\u7559\u7A7A\u5219\u4F7F\u7528\u9ED8\u8BA4\u8DEF\u5F84 /" value="/">
                <small style="display: block; margin-top: 6px; color: #86868b; font-size: 13px;">\u81EA\u5B9A\u4E49WebSocket\u8DEF\u5F84\uFF0C\u4F8B\u5982\uFF1A/v2ray \u6216 /</small>
            </div>
            
            <div class="switch-group">
                <label>\u542F\u7528\u4F18\u9009\u57DF\u540D</label>
                <div class="switch active" id="switchDomain" onclick="toggleSwitch('switchDomain')"></div>
            </div>
            
            <div class="switch-group">
                <label>\u542F\u7528\u4F18\u9009IP</label>
                <div class="switch active" id="switchIP" onclick="toggleSwitch('switchIP')"></div>
            </div>
            
            <div class="switch-group">
                <label>\u542F\u7528GitHub\u4F18\u9009</label>
                <div class="switch active" id="switchGitHub" onclick="toggleSwitch('switchGitHub')"></div>
            </div>
            
            <div class="form-group" id="githubUrlGroup" style="margin-top: 12px;">
                <label>GitHub\u4F18\u9009URL\uFF08\u53EF\u9009\uFF09</label>
                <input type="text" id="githubUrl" placeholder="\u7559\u7A7A\u5219\u4F7F\u7528\u9ED8\u8BA4\u5730\u5740" style="font-size: 15px;">
                <small style="display: block; margin-top: 6px; color: #86868b; font-size: 13px;">\u81EA\u5B9A\u4E49\u4F18\u9009IP\u5217\u8868\u6765\u6E90URL\uFF0C\u7559\u7A7A\u5219\u4F7F\u7528\u9ED8\u8BA4\u5730\u5740</small>
            </div>
            
            <div class="form-group" style="margin-top: 24px;">
                <label>\u534F\u8BAE\u9009\u62E9</label>
                <div style="display: flex; flex-direction: column; gap: 12px; margin-top: 8px;">
                    <div class="switch-group">
                        <label>VLESS (vl)</label>
                        <div class="switch active" id="switchVL" onclick="toggleSwitch('switchVL')"></div>
                    </div>
                    <div class="switch-group">
                        <label>Trojan (tj)</label>
                        <div class="switch" id="switchTJ" onclick="toggleSwitch('switchTJ')"></div>
                    </div>
                    <div class="switch-group">
                        <label>VMess (vm)</label>
                        <div class="switch" id="switchVM" onclick="toggleSwitch('switchVM')"></div>
                    </div>
                </div>
            </div>
            
            <div class="form-group" style="margin-top: 24px;">
                <label>\u5BA2\u6237\u7AEF\u9009\u62E9</label>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin-top: 8px;">
                    <button type="button" class="client-btn" onclick="generateClientLink('clash', 'CLASH')">CLASH</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('clash', 'STASH')">STASH</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('surge', 'SURGE')">SURGE</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('sing-box', 'SING-BOX')">SING-BOX</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('loon', 'LOON')">LOON</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('quanx', 'QUANTUMULT X')" style="font-size: 13px;">QUANTUMULT X</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'V2RAY')">V2RAY</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'V2RAYNG')">V2RAYNG</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'NEKORAY')">NEKORAY</button>
                    <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'Shadowrocket')" style="font-size: 13px;">Shadowrocket</button>
                </div>
                <div class="result-url" id="clientSubscriptionUrl" style="display: none; margin-top: 12px; padding: 12px; background: rgba(0, 122, 255, 0.1); border-radius: 8px; font-size: 13px; color: #007aff; word-break: break-all;"></div>
            </div>
            
            <div class="form-group">
                <label>IP\u7248\u672C\u9009\u62E9</label>
                <div style="display: flex; gap: 16px; margin-top: 8px;">
                    <label class="checkbox-label">
                        <input type="checkbox" id="ipv4Enabled" checked>
                        <span>IPv4</span>
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="ipv6Enabled" checked>
                        <span>IPv6</span>
                    </label>
                </div>
            </div>
            
            <div class="form-group">
                <label>\u8FD0\u8425\u5546\u9009\u62E9</label>
                <div style="display: flex; gap: 16px; flex-wrap: wrap; margin-top: 8px;">
                    <label class="checkbox-label">
                        <input type="checkbox" id="ispMobile" checked>
                        <span>\u79FB\u52A8</span>
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="ispUnicom" checked>
                        <span>\u8054\u901A</span>
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="ispTelecom" checked>
                        <span>\u7535\u4FE1</span>
                    </label>
                </div>
            </div>
            
            <div class="switch-group" style="margin-top: 20px;">
                <label>\u4EC5TLS\u8282\u70B9</label>
                <div class="switch" id="switchTLS" onclick="toggleSwitch('switchTLS')"></div>
            </div>
            <small style="display: block; margin-top: -12px; margin-bottom: 12px; color: #86868b; font-size: 13px; padding-left: 0;">\u542F\u7528\u540E\u53EA\u751F\u6210\u5E26TLS\u7684\u8282\u70B9\uFF0C\u4E0D\u751F\u6210\u975ETLS\u8282\u70B9\uFF08\u598280\u7AEF\u53E3\uFF09</small>
        </div>
        
        <div class="card" style="margin-top: 16px;">
            <div class="form-group">
                <label>\u5728\u7EBF\u5EF6\u8FDF\u6D4B\u8BD5</label>
                <input type="text" id="testHost" placeholder="\u8F93\u5165IP\u6216\u57DF\u540D\uFF0C\u4F8B\u5982: 1.1.1.1 \u6216 example.com" style="margin-bottom: 12px;">
                <div style="display: flex; gap: 10px; margin-bottom: 12px;">
                    <input type="number" id="testPort" placeholder="\u7AEF\u53E3" value="443" style="flex: 1; min-width: 0;">
                    <input type="number" id="testTimeout" placeholder="\u8D85\u65F6(ms)" value="5000" style="flex: 1; min-width: 0;">
                </div>
                <button type="button" class="btn btn-secondary" onclick="testSingleLatency()" id="testBtn" style="margin-top: 0;">\u6D4B\u8BD5\u5EF6\u8FDF</button>
                <div id="testResult" style="display: none; margin-top: 12px; padding: 12px; background: rgba(142, 142, 147, 0.12); border-radius: 8px; font-size: 14px;"></div>
            </div>
            
            <div class="form-group" style="margin-top: 24px;">
                <label>\u6279\u91CF\u6D4B\u8BD5\u5EF6\u8FDF</label>
                <textarea id="batchTestHosts" placeholder="\u6BCF\u884C\u4E00\u4E2AIP\u6216\u57DF\u540D\uFF0C\u4F8B\u5982\uFF1A&#10;1.1.1.1&#10;1.0.0.1&#10;example.com" style="width: 100%; padding: 14px 16px; font-size: 15px; font-weight: 400; color: #1d1d1f; background: rgba(142, 142, 147, 0.12); border: none; border-radius: 12px; outline: none; resize: vertical; min-height: 100px; font-family: inherit;"></textarea>
                <div style="display: flex; gap: 10px; margin-top: 12px;">
                    <input type="number" id="batchTestPort" placeholder="\u7AEF\u53E3" value="443" style="flex: 1; min-width: 0;">
                    <input type="number" id="batchTestTimeout" placeholder="\u8D85\u65F6(ms)" value="5000" style="flex: 1; min-width: 0;">
                </div>
                <button type="button" class="btn btn-secondary" onclick="testBatchLatency()" id="batchTestBtn" style="margin-top: 12px;">\u6279\u91CF\u6D4B\u8BD5</button>
                <div id="batchTestResult" style="display: none; margin-top: 12px; max-height: 400px; overflow-y: auto;"></div>
            </div>
        </div>
        
        <div class="footer">
            <p>\u7B80\u5316\u7248\u4F18\u9009\u5DE5\u5177 \u2022 \u4EC5\u7528\u4E8E\u8282\u70B9\u751F\u6210</p>
            <div style="margin-top: 20px; display: flex; justify-content: center; gap: 24px; flex-wrap: wrap;">
                <a href="https://github.com/byJoey/cfnew" target="_blank" style="color: #007aff; text-decoration: none; font-size: 15px; font-weight: 500;">GitHub \u9879\u76EE</a>
                <a href="https://www.youtube.com/@joeyblog" target="_blank" style="color: #007aff; text-decoration: none; font-size: 15px; font-weight: 500;">YouTube @joeyblog</a>
            </div>
        </div>
    </div>
    
    <script>
        let switches = {
            switchDomain: true,
            switchIP: true,
            switchGitHub: true,
            switchVL: true,
            switchTJ: false,
            switchVM: false,
            switchTLS: false
        };
        
        function toggleSwitch(id) {
            const switchEl = document.getElementById(id);
            switches[id] = !switches[id];
            switchEl.classList.toggle('active');
        }
        
        
        // \u8BA2\u9605\u8F6C\u6362\u5730\u5740\uFF08\u4ECE\u670D\u52A1\u5668\u6CE8\u5165\uFF09
        const SUB_CONVERTER_URL = "${scu2}";
        
        function tryOpenApp(schemeUrl, fallbackCallback, timeout) {
            timeout = timeout || 2500;
            let appOpened = false;
            let callbackExecuted = false;
            const startTime = Date.now();
            
            const blurHandler = () => {
                const elapsed = Date.now() - startTime;
                if (elapsed < 3000 && !callbackExecuted) {
                    appOpened = true;
                }
            };
            
            window.addEventListener('blur', blurHandler);
            
            const hiddenHandler = () => {
                const elapsed = Date.now() - startTime;
                if (elapsed < 3000 && !callbackExecuted) {
                    appOpened = true;
                }
            };
            
            document.addEventListener('visibilitychange', hiddenHandler);
            
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.style.width = '1px';
            iframe.style.height = '1px';
            iframe.src = schemeUrl;
            document.body.appendChild(iframe);
            
            setTimeout(() => {
                if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
                window.removeEventListener('blur', blurHandler);
                document.removeEventListener('visibilitychange', hiddenHandler);
                
                if (!callbackExecuted) {
                    callbackExecuted = true;
                    if (!appOpened && fallbackCallback) {
                        fallbackCallback();
                    }
                }
            }, timeout);
        }
        
        function generateClientLink(clientType, clientName) {
            const domain = document.getElementById('domain').value.trim();
            const uuid = document.getElementById('uuid').value.trim();
            const customPath = document.getElementById('customPath').value.trim() || '/';
            
            if (!domain || !uuid) {
                alert('\u8BF7\u5148\u586B\u5199\u57DF\u540D\u548CUUID');
                return;
            }
            
            if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid)) {
                alert('UUID\u683C\u5F0F\u4E0D\u6B63\u786E');
                return;
            }
            
            // \u68C0\u67E5\u81F3\u5C11\u9009\u62E9\u4E00\u4E2A\u534F\u8BAE
            if (!switches.switchVL && !switches.switchTJ && !switches.switchVM) {
                alert('\u8BF7\u81F3\u5C11\u9009\u62E9\u4E00\u4E2A\u534F\u8BAE\uFF08VLESS\u3001Trojan\u6216VMess\uFF09');
                return;
            }
            
            const ipv4Enabled = document.getElementById('ipv4Enabled').checked;
            const ipv6Enabled = document.getElementById('ipv6Enabled').checked;
            const ispMobile = document.getElementById('ispMobile').checked;
            const ispUnicom = document.getElementById('ispUnicom').checked;
            const ispTelecom = document.getElementById('ispTelecom').checked;
            
            const githubUrl = document.getElementById('githubUrl').value.trim();
            
            const currentUrl = new URL(window.location.href);
            const baseUrl = currentUrl.origin;
            let subscriptionUrl = \`\${baseUrl}/\${uuid}/sub?domain=\${encodeURIComponent(domain)}&epd=\${switches.switchDomain ? 'yes' : 'no'}&epi=\${switches.switchIP ? 'yes' : 'no'}&egi=\${switches.switchGitHub ? 'yes' : 'no'}\`;
            
            // \u6DFB\u52A0GitHub\u4F18\u9009URL
            if (githubUrl) {
                subscriptionUrl += \`&piu=\${encodeURIComponent(githubUrl)}\`;
            }
            
            // \u6DFB\u52A0\u534F\u8BAE\u9009\u62E9
            if (switches.switchVL) subscriptionUrl += '&ev=yes';
            if (switches.switchTJ) subscriptionUrl += '&et=yes';
            if (switches.switchVM) subscriptionUrl += '&vm=yes';
            
            if (!ipv4Enabled) subscriptionUrl += '&ipv4=no';
            if (!ipv6Enabled) subscriptionUrl += '&ipv6=no';
            if (!ispMobile) subscriptionUrl += '&ispMobile=no';
            if (!ispUnicom) subscriptionUrl += '&ispUnicom=no';
            if (!ispTelecom) subscriptionUrl += '&ispTelecom=no';
            
            // \u6DFB\u52A0TLS\u63A7\u5236
            if (switches.switchTLS) subscriptionUrl += '&dkby=yes';
            
            // \u6DFB\u52A0\u81EA\u5B9A\u4E49\u8DEF\u5F84
            if (customPath && customPath !== '/') {
                subscriptionUrl += \`&path=\${encodeURIComponent(customPath)}\`;
            }
            
            let finalUrl = subscriptionUrl;
            let schemeUrl = '';
            let displayName = clientName || '';
            
            if (clientType === 'v2ray') {
                finalUrl = subscriptionUrl;
                const urlElement = document.getElementById('clientSubscriptionUrl');
                urlElement.textContent = finalUrl;
                urlElement.style.display = 'block';
                
                if (clientName === 'V2RAY') {
                    navigator.clipboard.writeText(finalUrl).then(() => {
                        alert(displayName + ' \u8BA2\u9605\u94FE\u63A5\u5DF2\u590D\u5236');
                    });
                } else if (clientName === 'Shadowrocket') {
                    schemeUrl = 'shadowrocket://add/' + encodeURIComponent(finalUrl);
                    tryOpenApp(schemeUrl, () => {
                        navigator.clipboard.writeText(finalUrl).then(() => {
                            alert(displayName + ' \u8BA2\u9605\u94FE\u63A5\u5DF2\u590D\u5236');
                        });
                    });
                } else if (clientName === 'V2RAYNG') {
                    schemeUrl = 'v2rayng://install?url=' + encodeURIComponent(finalUrl);
                    tryOpenApp(schemeUrl, () => {
                        navigator.clipboard.writeText(finalUrl).then(() => {
                            alert(displayName + ' \u8BA2\u9605\u94FE\u63A5\u5DF2\u590D\u5236');
                        });
                    });
                } else if (clientName === 'NEKORAY') {
                    schemeUrl = 'nekoray://install-config?url=' + encodeURIComponent(finalUrl);
                    tryOpenApp(schemeUrl, () => {
                        navigator.clipboard.writeText(finalUrl).then(() => {
                            alert(displayName + ' \u8BA2\u9605\u94FE\u63A5\u5DF2\u590D\u5236');
                        });
                    });
                }
            } else {
                const encodedUrl = encodeURIComponent(subscriptionUrl);
                finalUrl = SUB_CONVERTER_URL + '?target=' + clientType + '&url=' + encodedUrl + '&insert=false&emoji=true&list=false&xudp=false&udp=false&tfo=false&expand=true&scv=false&fdn=false&new_name=true';
                
                const urlElement = document.getElementById('clientSubscriptionUrl');
                urlElement.textContent = finalUrl;
                urlElement.style.display = 'block';
                
                if (clientType === 'clash') {
                    if (clientName === 'STASH') {
                        schemeUrl = 'stash://install?url=' + encodeURIComponent(finalUrl);
                        displayName = 'STASH';
                    } else {
                        schemeUrl = 'clash://install-config?url=' + encodeURIComponent(finalUrl);
                        displayName = 'CLASH';
                    }
                } else if (clientType === 'surge') {
                    schemeUrl = 'surge:///install-config?url=' + encodeURIComponent(finalUrl);
                    displayName = 'SURGE';
                } else if (clientType === 'sing-box') {
                    schemeUrl = 'sing-box://install-config?url=' + encodeURIComponent(finalUrl);
                    displayName = 'SING-BOX';
                } else if (clientType === 'loon') {
                    schemeUrl = 'loon://install?url=' + encodeURIComponent(finalUrl);
                    displayName = 'LOON';
                } else if (clientType === 'quanx') {
                    schemeUrl = 'quantumult-x://install-config?url=' + encodeURIComponent(finalUrl);
                    displayName = 'QUANTUMULT X';
                }
                
                if (schemeUrl) {
                    tryOpenApp(schemeUrl, () => {
                        navigator.clipboard.writeText(finalUrl).then(() => {
                            alert(displayName + ' \u8BA2\u9605\u94FE\u63A5\u5DF2\u590D\u5236');
                        });
                    });
                } else {
                    navigator.clipboard.writeText(finalUrl).then(() => {
                        alert(displayName + ' \u8BA2\u9605\u94FE\u63A5\u5DF2\u590D\u5236');
                    });
                }
            }
        }
        
        // \u5355\u4E2A\u5EF6\u8FDF\u6D4B\u8BD5
        async function testSingleLatency() {
            const host = document.getElementById('testHost').value.trim();
            const port = parseInt(document.getElementById('testPort').value) || 443;
            const timeout = parseInt(document.getElementById('testTimeout').value) || 5000;
            const testBtn = document.getElementById('testBtn');
            const testResult = document.getElementById('testResult');
            
            if (!host) {
                alert('\u8BF7\u8F93\u5165\u8981\u6D4B\u8BD5\u7684IP\u6216\u57DF\u540D');
                return;
            }
            
            testBtn.disabled = true;
            testBtn.textContent = '\u6D4B\u8BD5\u4E2D...';
            testResult.style.display = 'none';
            
            try {
                const currentUrl = new URL(window.location.href);
                const baseUrl = currentUrl.origin;
                const testUrl = \`\${baseUrl}/test?host=\${encodeURIComponent(host)}&port=\${port}&timeout=\${timeout}\`;
                
                const response = await fetch(testUrl);
                const result = await response.json();
                
                testResult.style.display = 'block';
                
                if (result.success) {
                    testResult.innerHTML = \`
                        <div style="color: #34c759; font-weight: 600; margin-bottom: 8px;">\u2713 \u6D4B\u8BD5\u6210\u529F</div>
                        <div style="color: #1d1d1f; margin-bottom: 4px;"><strong>\u5EF6\u8FDF:</strong> \${result.latency}ms</div>
                        \${result.ip ? \`<div style="color: #1d1d1f; margin-bottom: 4px;"><strong>IP:</strong> \${result.ip}</div>\` : ''}
                        \${result.location ? \`<div style="color: #1d1d1f; margin-bottom: 4px;"><strong>\u4F4D\u7F6E:</strong> \${result.location}</div>\` : ''}
                        \${result.colo ? \`<div style="color: #1d1d1f;"><strong>\u6570\u636E\u4E2D\u5FC3:</strong> \${result.colo}</div>\` : ''}
                    \`;
                    testResult.style.background = 'rgba(52, 199, 89, 0.1)';
                } else {
                    testResult.innerHTML = \`
                        <div style="color: #ff3b30; font-weight: 600; margin-bottom: 8px;">\u2717 \u6D4B\u8BD5\u5931\u8D25</div>
                        <div style="color: #1d1d1f; margin-bottom: 4px;"><strong>\u5EF6\u8FDF:</strong> \${result.latency}ms</div>
                        <div style="color: #1d1d1f;"><strong>\u9519\u8BEF:</strong> \${result.error || '\u672A\u77E5\u9519\u8BEF'}</div>
                    \`;
                    testResult.style.background = 'rgba(255, 59, 48, 0.1)';
                }
            } catch (error) {
                testResult.style.display = 'block';
                testResult.innerHTML = \`
                    <div style="color: #ff3b30; font-weight: 600;">\u2717 \u6D4B\u8BD5\u5931\u8D25</div>
                    <div style="color: #1d1d1f; margin-top: 4px;">\${error.message || '\u7F51\u7EDC\u9519\u8BEF'}</div>
                \`;
                testResult.style.background = 'rgba(255, 59, 48, 0.1)';
            } finally {
                testBtn.disabled = false;
                testBtn.textContent = '\u6D4B\u8BD5\u5EF6\u8FDF';
            }
        }
        
        // \u6279\u91CF\u5EF6\u8FDF\u6D4B\u8BD5
        async function testBatchLatency() {
            const hostsText = document.getElementById('batchTestHosts').value.trim();
            const port = parseInt(document.getElementById('batchTestPort').value) || 443;
            const timeout = parseInt(document.getElementById('batchTestTimeout').value) || 5000;
            const batchTestBtn = document.getElementById('batchTestBtn');
            const batchTestResult = document.getElementById('batchTestResult');
            
            if (!hostsText) {
                alert('\u8BF7\u8F93\u5165\u8981\u6D4B\u8BD5\u7684IP\u6216\u57DF\u540D\u5217\u8868');
                return;
            }
            
            const hosts = hostsText.split('\\n')
                .map(line => line.trim())
                .filter(line => line.length > 0);
            
            if (hosts.length === 0) {
                alert('\u8BF7\u8F93\u5165\u81F3\u5C11\u4E00\u4E2AIP\u6216\u57DF\u540D');
                return;
            }
            
            batchTestBtn.disabled = true;
            batchTestBtn.textContent = \`\u6D4B\u8BD5\u4E2D... (0/\${hosts.length})\`;
            batchTestResult.style.display = 'none';
            batchTestResult.innerHTML = '';
            
            try {
                const currentUrl = new URL(window.location.href);
                const baseUrl = currentUrl.origin;
                
                const response = await fetch(\`\${baseUrl}/batch-test\`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        hosts: hosts,
                        port: port,
                        timeout: timeout,
                        concurrency: 5
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    batchTestResult.style.display = 'block';
                    let html = \`
                        <div style="padding: 12px; background: rgba(142, 142, 147, 0.12); border-radius: 8px; margin-bottom: 12px;">
                            <div style="font-weight: 600; margin-bottom: 4px;">\u6D4B\u8BD5\u5B8C\u6210</div>
                            <div style="font-size: 13px; color: #86868b;">\u6210\u529F: \${data.successCount} / \u603B\u8BA1: \${data.total}</div>
                        </div>
                    \`;
                    
                    data.results.forEach((result, index) => {
                        const bgColor = result.success ? 'rgba(52, 199, 89, 0.1)' : 'rgba(255, 59, 48, 0.1)';
                        const statusColor = result.success ? '#34c759' : '#ff3b30';
                        const statusText = result.success ? '\u2713' : '\u2717';
                        
                        html += \`
                            <div style="padding: 12px; background: \${bgColor}; border-radius: 8px; margin-bottom: 8px;">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                    <div style="font-weight: 600; color: \${statusColor};">\${statusText} \${result.host}:\${result.port}</div>
                                    <div style="font-weight: 600; color: #1d1d1f;">\${result.latency}ms</div>
                                </div>
                                \${result.success ? \`
                                    \${result.ip ? \`<div style="font-size: 13px; color: #86868b;">IP: \${result.ip}</div>\` : ''}
                                    \${result.location ? \`<div style="font-size: 13px; color: #86868b;">\u4F4D\u7F6E: \${result.location}</div>\` : ''}
                                    \${result.colo ? \`<div style="font-size: 13px; color: #86868b;">\u6570\u636E\u4E2D\u5FC3: \${result.colo}</div>\` : ''}
                                \` : \`
                                    <div style="font-size: 13px; color: #ff3b30;">\u9519\u8BEF: \${result.error || '\u672A\u77E5\u9519\u8BEF'}</div>
                                \`}
                            </div>
                        \`;
                    });
                    
                    batchTestResult.innerHTML = html;
                } else {
                    batchTestResult.style.display = 'block';
                    batchTestResult.innerHTML = \`
                        <div style="padding: 12px; background: rgba(255, 59, 48, 0.1); border-radius: 8px; color: #ff3b30;">
                            \u6D4B\u8BD5\u5931\u8D25: \${data.error || '\u672A\u77E5\u9519\u8BEF'}
                        </div>
                    \`;
                }
            } catch (error) {
                batchTestResult.style.display = 'block';
                batchTestResult.innerHTML = \`
                    <div style="padding: 12px; background: rgba(255, 59, 48, 0.1); border-radius: 8px; color: #ff3b30;">
                        \u7F51\u7EDC\u9519\u8BEF: \${error.message || '\u672A\u77E5\u9519\u8BEF'}
                    </div>
                \`;
            } finally {
                batchTestBtn.disabled = false;
                batchTestBtn.textContent = '\u6279\u91CF\u6D4B\u8BD5';
            }
        }
        
        // \u652F\u6301\u56DE\u8F66\u952E\u89E6\u53D1\u6D4B\u8BD5
        document.addEventListener('DOMContentLoaded', function() {
            const testHostInput = document.getElementById('testHost');
            if (testHostInput) {
                testHostInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        testSingleLatency();
                    }
                });
            }
        });
    <\/script>
</body>
</html>`;
}
__name(generateHomePage, "generateHomePage");
var worker_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/" || path === "") {
      const scuValue = env?.scu || scu;
      return new Response(generateHomePage(scuValue), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/test") {
      const host = url.searchParams.get("host");
      const port = parseInt(url.searchParams.get("port") || "443");
      const timeout = parseInt(url.searchParams.get("timeout") || "5000");
      if (!host) {
        return new Response(JSON.stringify({
          success: false,
          error: "\u7F3A\u5C11host\u53C2\u6570"
        }), {
          status: 400,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      const result = await testLatency(host, port, timeout);
      return new Response(JSON.stringify(result, null, 2), {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type"
        }
      });
    }
    if (path === "/batch-test") {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
          }
        });
      }
      if (request.method === "POST") {
        try {
          const body = await request.json();
          const hosts = body.hosts || [];
          const port = parseInt(body.port || "443");
          const timeout = parseInt(body.timeout || "5000");
          const concurrency = parseInt(body.concurrency || "5");
          if (!Array.isArray(hosts) || hosts.length === 0) {
            return new Response(JSON.stringify({
              success: false,
              error: "hosts\u5FC5\u987B\u662F\u975E\u7A7A\u6570\u7EC4"
            }), {
              status: 400,
              headers: {
                "Content-Type": "application/json; charset=utf-8",
                "Access-Control-Allow-Origin": "*"
              }
            });
          }
          const results = await batchTestLatency(hosts, port, timeout, concurrency);
          return new Response(JSON.stringify({
            success: true,
            results,
            total: results.length,
            successCount: results.filter((r) => r.success).length
          }, null, 2), {
            headers: {
              "Content-Type": "application/json; charset=utf-8",
              "Access-Control-Allow-Origin": "*"
            }
          });
        } catch (error) {
          return new Response(JSON.stringify({
            success: false,
            error: error.message
          }), {
            status: 500,
            headers: {
              "Content-Type": "application/json; charset=utf-8",
              "Access-Control-Allow-Origin": "*"
            }
          });
        }
      }
    }
    if (path === "/test-optimize-api") {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
          }
        });
      }
      const apiUrl = url.searchParams.get("url");
      const port = url.searchParams.get("port") || "443";
      const timeout = parseInt(url.searchParams.get("timeout") || "3000");
      if (!apiUrl) {
        return new Response(JSON.stringify({
          success: false,
          error: "\u7F3A\u5C11url\u53C2\u6570"
        }), {
          status: 400,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*"
          }
        });
      }
      try {
        const results = await \u8BF7\u6C42\u4F18\u9009API([apiUrl], port, timeout);
        return new Response(JSON.stringify({
          success: true,
          results,
          total: results.length,
          message: `\u6210\u529F\u83B7\u53D6 ${results.length} \u4E2A\u4F18\u9009IP`
        }, null, 2), {
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*"
          }
        });
      } catch (error) {
        return new Response(JSON.stringify({
          success: false,
          error: error.message
        }), {
          status: 500,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*"
          }
        });
      }
    }
    const pathMatch = path.match(/^\/([^\/]+)\/sub$/);
    if (pathMatch) {
      const uuid = pathMatch[1];
      if (!isValidUUID(uuid)) {
        return new Response("\u65E0\u6548\u7684UUID\u683C\u5F0F", { status: 400 });
      }
      const domain = url.searchParams.get("domain");
      if (!domain) {
        return new Response("\u7F3A\u5C11\u57DF\u540D\u53C2\u6570", { status: 400 });
      }
      epd = url.searchParams.get("epd") !== "no";
      epi = url.searchParams.get("epi") !== "no";
      egi = url.searchParams.get("egi") !== "no";
      const piu = url.searchParams.get("piu") || defaultIPURL;
      const evEnabled = url.searchParams.get("ev") === "yes" || url.searchParams.get("ev") === null && ev;
      const etEnabled = url.searchParams.get("et") === "yes";
      const vmEnabled = url.searchParams.get("vm") === "yes";
      const ipv4Enabled = url.searchParams.get("ipv4") !== "no";
      const ipv6Enabled = url.searchParams.get("ipv6") !== "no";
      const ispMobile = url.searchParams.get("ispMobile") !== "no";
      const ispUnicom = url.searchParams.get("ispUnicom") !== "no";
      const ispTelecom = url.searchParams.get("ispTelecom") !== "no";
      const disableNonTLS = url.searchParams.get("dkby") === "yes";
      const customPath = url.searchParams.get("path") || "/";
      return await handleSubscriptionRequest(request, uuid, domain, piu, ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom, evEnabled, etEnabled, vmEnabled, disableNonTLS, customPath);
    }
    return new Response("Not Found", { status: 404 });
  }
};
export {
  worker_default as default
};
//# sourceMappingURL=_worker.js.map
