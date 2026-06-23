/* ===================== GLOBAL STATE ===================== */
let projection = null;
let pathGenerator = null;
let svgRoot = null;
let investigations = [];

const MAP_W = 1000, MAP_H = 640;

/* ===================== CLOCK ===================== */
function tickClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toUTCString().split(' ')[4] + ' UTC';
}
setInterval(tickClock, 1000);
tickClock();

/* ===================== REAL WORLD MAP (D3 + world-atlas) ===================== */
async function loadWorldMap() {
  const mapWrap = document.getElementById('mapWrap');
  try {
    const world = await d3.json('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-50m.json');
    const land = topojson.feature(world, world.objects.countries);

    projection = d3.geoEquirectangular().fitSize([MAP_W, MAP_H], land);
    pathGenerator = d3.geoPath(projection);

    const svg = d3.select(mapWrap)
      .append('svg')
      .attr('viewBox', `0 0 ${MAP_W} ${MAP_H}`)
      .attr('preserveAspectRatio', 'xMidYMid meet');

    svg.append('rect').attr('width', MAP_W).attr('height', MAP_H).attr('fill', '#000');

    const graticule = d3.geoGraticule().step([20, 20]);
    svg.append('path')
      .datum(graticule())
      .attr('d', pathGenerator)
      .attr('fill', 'none')
      .attr('stroke', '#2a1015')
      .attr('stroke-width', 0.5);

    svg.append('g')
      .selectAll('path')
      .data(land.features)
      .join('path')
      .attr('d', pathGenerator)
      .attr('fill', '#2c2d30')
      .attr('stroke', '#52555a')
      .attr('stroke-width', 0.6);

    svg.append('g').attr('id', 'arcLayer');
    svg.append('g').attr('id', 'markerLayer');

    svgRoot = svg;
    document.getElementById('mapLoading').style.display = 'none';

    refreshAll();
  } catch (err) {
    document.getElementById('mapLoading').textContent = 'MAP LOAD FAILED — CHECK INTERNET CONNECTION';
    console.error('World map load error:', err);
  }
}

function plotMarkersAndArcs(invs) {
  if (!svgRoot || !projection) return;

  const HQ = [78.4867, 17.3850]; // fixed SOC "home" reference point for arc origin
  const hq = projection(HQ);

  const arcLayer = svgRoot.select('#arcLayer');
  const markerLayer = svgRoot.select('#markerLayer');
  arcLayer.selectAll('*').remove();
  markerLayer.selectAll('*').remove();

  const colorFor = (verdict) => verdict === 'malicious' ? '#ff1e3c' : verdict === 'suspicious' ? '#ffa726' : '#2ed573';

  invs.forEach(r => {
    if (!r.geo || r.geo.lat == null || r.geo.lon == null) return;
    const pt = projection([r.geo.lon, r.geo.lat]);
    if (!pt) return;
    const color = colorFor(r.verdict);

    if (r.verdict !== 'clean' && hq) {
      const mid = [(hq[0] + pt[0]) / 2, Math.min(hq[1], pt[1]) - 60];
      const d = `M ${hq[0]},${hq[1]} Q ${mid[0]},${mid[1]} ${pt[0]},${pt[1]}`;
      const path = arcLayer.append('path')
        .attr('d', d)
        .attr('fill', 'none')
        .attr('stroke', color)
        .attr('stroke-width', 1.2)
        .attr('opacity', 0.55);

      const len = path.node().getTotalLength();
      path.attr('stroke-dasharray', `${len}`)
        .attr('stroke-dashoffset', len)
        .transition().duration(1400)
        .attr('stroke-dashoffset', 0);
    }

    const g = markerLayer.append('g');
    const pulse = g.append('circle')
      .attr('cx', pt[0]).attr('cy', pt[1]).attr('r', 5)
      .attr('fill', 'none').attr('stroke', color).attr('stroke-width', 1).attr('opacity', 0.6);
    pulse.append('animate').attr('attributeName', 'r').attr('values', '5;16;5').attr('dur', '2s').attr('repeatCount', 'indefinite');
    pulse.append('animate').attr('attributeName', 'opacity').attr('values', '0.6;0;0.6').attr('dur', '2s').attr('repeatCount', 'indefinite');

    const dot = g.append('circle')
      .attr('cx', pt[0]).attr('cy', pt[1]).attr('r', 3.5)
      .attr('fill', color)
      .style('filter', `drop-shadow(0 0 4px ${color})`);
    dot.append('title').text(`${r.ioc} — ${r.geo.city || ''}, ${r.geo.country || ''}`);
  });

  if (hq) {
    const hqDot = markerLayer.append('circle')
      .attr('cx', hq[0]).attr('cy', hq[1]).attr('r', 5)
      .attr('fill', '#3ddcff').style('filter', 'drop-shadow(0 0 6px #3ddcff)');
    hqDot.append('title').text('SOC — Home Base');
  }
}

/* ===================== CHARTS ===================== */
let analyticsChart, attackTypesChart, trafficChart;

function buildCharts() {
  const chartFont = { family: "'Share Tech Mono', monospace", size: 10 };
  const gridColor = '#2a2c30';
  const textColor = '#707680';

  analyticsChart = new Chart(document.getElementById('analyticsChart'), {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Investigations',
        data: [],
        borderColor: '#ff1e3c',
        backgroundColor: 'rgba(255,30,60,0.12)',
        fill: true,
        tension: 0.35,
        pointRadius: 0,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: textColor, font: chartFont }, grid: { color: gridColor } },
        y: { ticks: { color: textColor, font: chartFont }, grid: { color: gridColor }, beginAtZero: true }
      }
    }
  });

  attackTypesChart = new Chart(document.getElementById('attackTypesChart'), {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: '#ff1e3c',
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: textColor, font: chartFont }, grid: { color: gridColor }, beginAtZero: true },
        y: { ticks: { color: textColor, font: chartFont }, grid: { display: false } }
      }
    }
  });

  trafficChart = new Chart(document.getElementById('trafficChart'), {
    type: 'line',
    data: {
      labels: Array.from({ length: 20 }, (_, i) => i),
      datasets: [{
        data: Array.from({ length: 20 }, () => Math.floor(Math.random() * 8000 + 2000)),
        borderColor: '#3ddcff',
        backgroundColor: 'rgba(61,220,255,0.1)',
        fill: true,
        tension: 0.4,
        pointRadius: 0,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { display: false },
        y: { ticks: { color: textColor, font: chartFont }, grid: { color: gridColor } }
      }
    }
  });

  setInterval(() => {
    const data = trafficChart.data.datasets[0].data;
    data.shift();
    data.push(Math.floor(Math.random() * 8000 + 2000));
    trafficChart.update();
  }, 2000);
}

function updateAnalyticsChart(invs) {
  const buckets = {};
  invs.forEach(r => {
    const hour = new Date(r.timestamp).toISOString().slice(11, 16);
    buckets[hour] = (buckets[hour] || 0) + 1;
  });
  const labels = Object.keys(buckets).slice(-12);
  analyticsChart.data.labels = labels;
  analyticsChart.data.datasets[0].data = labels.map(l => buckets[l]);
  analyticsChart.update();
}

function updateAttackTypesChart(invs) {
  const counts = {};
  invs.forEach(r => {
    const cat = r.threat_category && r.threat_category !== 'none' ? r.threat_category : null;
    if (cat) counts[cat] = (counts[cat] || 0) + 1;
  });
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  attackTypesChart.data.labels = entries.map(e => e[0]);
  attackTypesChart.data.datasets[0].data = entries.map(e => e[1]);
  attackTypesChart.update();
}

/* ===================== LIVE PACKET CAPTURE (simulated terminal) ===================== */
const PROTOCOLS = ['TCP', 'UDP', 'TLS 1.3', 'ICMP'];
function randomIp() {
  return Array.from({ length: 4 }, () => Math.floor(Math.random() * 255)).join('.');
}

function pushTerminalLine(highRisk) {
  const body = document.getElementById('terminalBody');
  if (!body) return;
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const src = randomIp(), dst = randomIp();
  const proto = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
  const tag = highRisk ? `<span class="high-risk">[HIGH RISK]</span>` : `[INFO]`;
  const extra = highRisk ? 'Malicious Signature Detected' : `${proto}, ${Math.floor(Math.random()*4000)}, ${Math.floor(Math.random()*400)}`;
  const line = document.createElement('div');
  line.className = 'line';
  line.innerHTML = `${ts} ${tag} ${src} &rarr; ${dst} [${proto}] ${extra}`;
  body.appendChild(line);
  while (body.children.length > 40) body.removeChild(body.firstChild);
  body.scrollTop = body.scrollHeight;
}

function startPacketCapture() {
  setInterval(() => pushTerminalLine(Math.random() < 0.25), 700);
}

/* ===================== TABLES ===================== */
function renderSrcDest(invs) {
  const body = document.getElementById('srcDestBody');
  if (!body) return;
  const rows = invs.slice(0, 8).map(r => `
    <tr>
      <td>${randomIp()}</td>
      <td>${r.ioc}</td>
      <td>${PROTOCOLS[0]}</td>
    </tr>
  `).join('');
  body.innerHTML = rows || `<tr><td colspan="3" style="color:#707680;text-align:center;">No data</td></tr>`;
}

function renderAlerts(invs) {
  const body = document.getElementById('alertsBody');
  if (!body) return;
  const alerts = invs.filter(r => r.verdict !== 'clean').slice(0, 8);
  body.innerHTML = alerts.map(r => `
    <tr>
      <td>${new Date(r.timestamp).toLocaleTimeString()}</td>
      <td class="${r.verdict === 'malicious' ? 'risk-high' : 'risk-mid'}">${r.ioc}</td>
      <td>${randomIp()}</td>
    </tr>
  `).join('') || `<tr><td colspan="3" style="color:#707680;text-align:center;">No alerts</td></tr>`;
}

function renderIocFeed(invs) {
  const body = document.getElementById('iocFeedBody');
  if (!body) return;
  body.innerHTML = invs.slice(0, 10).map(r => `
    <tr>
      <td>${r.ioc}</td>
      <td class="${r.verdict === 'malicious' ? 'risk-high' : r.verdict === 'suspicious' ? 'risk-mid' : ''}">${r.verdict}</td>
      <td>${r.ioc_type}</td>
      <td><a class="report-link" href="/api/report/${r.id}" title="Download PDF">&#9660;</a></td>
    </tr>
  `).join('') || `<tr><td colspan="4" style="color:#707680;text-align:center;">No IOCs yet</td></tr>`;
}

function verdictBadge(verdict) {
  return `<span class="badge ${verdict}">${verdict}</span>`;
}

function renderInvTable(invs) {
  const tableBody = document.getElementById('invTableBody');
  if (!invs.length) {
    tableBody.innerHTML = `<tr class="empty-row"><td colspan="8">No investigations yet. Analyze an IOC to get started.</td></tr>`;
    return;
  }
  tableBody.innerHTML = invs.map(r => `
    <tr>
      <td>${r.ioc}</td>
      <td>${r.ioc_type}</td>
      <td>${verdictBadge(r.verdict)}</td>
      <td>${r.threat_category}</td>
      <td>${r.mitre ? r.mitre.technique_id + ' — ' + r.mitre.technique_name : '-'}</td>
      <td>${r.geo ? (r.geo.country || '-') : '-'}</td>
      <td>${new Date(r.timestamp).toLocaleString()}</td>
      <td><a class="report-link" href="/api/report/${r.id}">Download PDF</a></td>
    </tr>
  `).join('');
}

function renderStats(stats) {
  document.getElementById('statTotal').textContent = stats.total;
  document.getElementById('statMalicious').textContent = stats.malicious;
  document.getElementById('statSuspicious').textContent = stats.suspicious;
  document.getElementById('statClean').textContent = stats.clean;
}

/* ===================== DATA REFRESH ===================== */
async function refreshAll() {
  const [invRes, statsRes] = await Promise.all([
    fetch('/api/investigations'),
    fetch('/api/stats')
  ]);
  investigations = await invRes.json();
  const stats = await statsRes.json();

  renderStats(stats);
  renderSrcDest(investigations);
  renderAlerts(investigations);
  renderIocFeed(investigations);
  updateAnalyticsChart(investigations);
  updateAttackTypesChart(investigations);
  plotMarkersAndArcs(investigations);
}

/* ===================== FORM ===================== */
const form = document.getElementById('analyzeForm');
const iocInput = document.getElementById('iocInput');
const iocType = document.getElementById('iocType');
const analyzeBtn = document.getElementById('analyzeBtn');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const ioc = iocInput.value.trim();
  if (!ioc) return;

  analyzeBtn.disabled = true;
  analyzeBtn.textContent = 'ANALYZING...';

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ioc, ioc_type: iocType.value })
    });
    if (!res.ok) throw new Error('Analysis failed');
    iocInput.value = '';
    await refreshAll();
  } catch (err) {
    alert('Error analyzing IOC: ' + err.message);
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'ANALYZE';
  }
});

document.getElementById('terminalClose')?.addEventListener('click', () => {
  document.getElementById('terminalOverlay').style.display = 'none';
});

/* ===================== INIT ===================== */
buildCharts();
startPacketCapture();
loadWorldMap();
