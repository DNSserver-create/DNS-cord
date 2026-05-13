const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const dnsPacket = require('dns-packet');

const PORT = process.env.PORT || 10000;

// カスタムルール（ここを自由に編集）
const CUSTOM_RULES = {
  'example.com': 'youtube.com',
  'test.local': 'youtube.com'
};

// Google DNS
const UPSTREAM_DNS = '8.8.8.8';

// DNS-over-HTTPS サーバー作成
const server = http.createServer(async (req, res) => {
  
  // CORSヘッダー
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // DNSクエリエンドポイント
  if (req.url === '/dns-query' || req.url.startsWith('/dns-query?')) {
    try {
      await handleDNSQuery(req, res);
    } catch (err) {
      console.error('DNS Error:', err);
      res.writeHead(500);
      res.end('Internal Server Error');
    }
    return;
  }

  // ヘルスチェック用
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      status: 'ok', 
      rules: Object.keys(CUSTOM_RULES),
      uptime: process.uptime()
    }));
    return;
  }

  // その他
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(`
    <h1>DNS-over-HTTPS Server</h1>
    <p>Endpoint: /dns-query</p>
    <p>Custom Rules: ${JSON.stringify(CUSTOM_RULES)}</p>
  `);
});

async function handleDNSQuery(req, res) {
  let dnsQuery;

  if (req.method === 'POST') {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    dnsQuery = Buffer.concat(chunks);
  } else if (req.method === 'GET') {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const dnsParam = url.searchParams.get('dns');
    if (!dnsParam) {
      res.writeHead(400);
      res.end('Missing dns parameter');
      return;
    }
    dnsQuery = Buffer.from(dnsParam.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  }

  const query = dnsPacket.decode(dnsQuery);
  console.log(`Query: ${query.questions?.[0]?.name} (${query.questions?.[0]?.type})`);

  const response = await resolveDNS(query);
  const responseBuffer = dnsPacket.encode(response);

  res.setHeader('Content-Type', 'application/dns-message');
  res.setHeader('Content-Length', responseBuffer.length);
  res.writeHead(200);
  res.end(responseBuffer);
}

async function resolveDNS(query) {
  const response = {
    type: 'response',
    id: query.id,
    flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
    questions: query.questions,
    answers: [],
    authorities: [],
    additionals: []
  };

  for (const question of query.questions) {
    const domain = question.name;

    // カスタムルールチェック
    if (CUSTOM_RULES[domain] && question.type === 'A') {
      const targetDomain = CUSTOM_RULES[domain];
      console.log(`Custom: ${domain} → ${targetDomain}`);

      try {
        const addresses = await dns.resolve4(targetDomain);
        if (addresses.length > 0) {
          response.answers.push({
            name: domain,
            type: 'A',
            class: 'IN',
            ttl: 300,
            data: addresses[0]
          });
        }
      } catch (err) {
        console.error(`Failed to resolve ${targetDomain}:`, err);
      }
    } 
    // AAAA（IPv6）もカスタムルール適用
    else if (CUSTOM_RULES[domain] && question.type === 'AAAA') {
      const targetDomain = CUSTOM_RULES[domain];
      try {
        const addresses = await dns.resolve6(targetDomain);
        if (addresses.length > 0) {
          response.answers.push({
            name: domain,
            type: 'AAAA',
            class: 'IN',
            ttl: 300,
            data: addresses[0]
          });
        }
      } catch (err) {
        // IPv6がない場合はスキップ
      }
    }
    // それ以外はGoogle DNSにフォワード
    else {
      const result = await forwardToUpstream(query);
      if (result.answers) {
        response.answers.push(...result.answers);
      }
    }
  }

  return response;
}

function forwardToUpstream(query) {
  return new Promise((resolve, reject) => {
    const socket = require('dgram').createSocket('udp4');
    const queryBuffer = dnsPacket.encode(query);

    socket.send(queryBuffer, 53, UPSTREAM_DNS, (err) => {
      if (err) reject(err);
    });

    socket.on('message', (msg) => {
      resolve(dnsPacket.decode(msg));
      socket.close();
    });

    socket.on('error', (err) => {
      reject(err);
    });

    setTimeout(() => {
      socket.close();
      reject(new Error('Timeout'));
    }, 5000);
  });
}

server.listen(PORT, () => {
  console.log(`DNS-over-HTTPS Server running on port ${PORT}`);
  console.log(`Custom rules:`, CUSTOM_RULES);
});
