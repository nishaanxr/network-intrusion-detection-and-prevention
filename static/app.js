const ATTACK_COLORS = {
  "DoS/Flood Attack":    { fill: "#f85149", max: 1000 },
  "Port Scan":           { fill: "#d29922", max: 50 },
  "Brute Force Attempt": { fill: "#79c0ff", max: 20 },
  "ICMP Packet":         { fill: "#8957e5", max: 200 },
};

const TAG_CLASS = {
  "DoS/Flood Attack":    "tag-dos",
  "Port Scan":           "tag-scan",
  "Brute Force Attempt": "tag-brute",
  "ICMP Packet":         "tag-icmp",
};

const COUNTRY_CACHE = {};
let previousAlertCount = 0;
let audioCtx = null;
let timelineChart = null;

function getAudioContext() {
  if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  return audioCtx;
}

function playAlert() {
  try {
    const ctx = getAudioContext();
    const oscillator = ctx.createOscillator();
    const gainNode = ctx.createGain();
    oscillator.connect(gainNode);
    gainNode.connect(ctx.destination);
    oscillator.type = "sine";
    oscillator.frequency.setValueAtTime(880, ctx.currentTime);
    oscillator.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.3);
    gainNode.gain.setValueAtTime(0.3, ctx.currentTime);
    gainNode.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
    oscillator.start(ctx.currentTime);
    oscillator.stop(ctx.currentTime + 0.4);
  } catch (e) {}
}

async function getGeoIP(ip) {
  if (COUNTRY_CACHE[ip]) return COUNTRY_CACHE[ip];
  try {
    const res = await fetch(`/api/geoip/${ip}`);
    const data = await res.json();
    const flag = data.countryCode
      ? String.fromCodePoint(...[...data.countryCode.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0)))
      : "🌐";
    const label = `${flag} ${data.city || data.country || "Unknown"}`;
    COUNTRY_CACHE[ip] = label;
    return label;
  } catch {
    return "🌐 Unknown";
  }
}

function exportCSV() {
  fetch("/api/stats")
    .then(r => r.json())
    .then(data => {
      const rows = [["Time", "Attack Type", "Source IP", "Detail"]];
      for (const a of data.recent_alerts) {
        rows.push([a.time, a.type, a.src, a.detail]);
      }
      const csv = rows.map(r => r.map(v => `"${v}"`).join(",")).join("\n");
      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ids_alerts_${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    });
}

function updateTimestamp() {
  document.getElementById("timestamp").textContent =
    new Date().toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "medium" });
}

async function fetchTimeline() {
  try {
    const res = await fetch("/api/timeline");
    const data = await res.json();

    const peak = Math.max(...data.values);
    document.getElementById("peak-label").textContent =
      peak > 0 ? `Peak: ${peak} attacks/min` : "";

    if (!timelineChart) {
      const ctx = document.getElementById("timelineChart").getContext("2d");
      timelineChart = new Chart(ctx, {
        type: "line",
        data: {
          labels: data.labels,
          datasets: [{
            label: "Attacks/min",
            data: data.values,
            borderColor: "#f85149",
            backgroundColor: "rgba(248,81,73,0.08)",
            borderWidth: 2,
            pointRadius: 3,
            pointBackgroundColor: "#f85149",
            fill: true,
            tension: 0.4
          }]
        },
        options: {
          responsive: true,
          animation: { duration: 500 },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "#161b22",
              borderColor: "#30363d",
              borderWidth: 1,
              titleColor: "#e6edf3",
              bodyColor: "#8b949e",
              callbacks: {
                label: ctx => ` ${ctx.parsed.y} attacks`
              }
            }
          },
          scales: {
            x: {
              grid: { color: "#21262d" },
              ticks: { color: "#8b949e", font: { size: 11 } }
            },
            y: {
              grid: { color: "#21262d" },
              ticks: { color: "#8b949e", font: { size: 11 }, stepSize: 1 },
              beginAtZero: true
            }
          }
        }
      });
    } else {
      timelineChart.data.labels = data.labels;
      timelineChart.data.datasets[0].data = data.values;
      timelineChart.update();
    }
  } catch (e) {
    console.error("Timeline fetch failed:", e);
  }
}

async function fetchStats() {
  try {
    const res = await fetch("/api/stats");
    const data = await res.json();

    if (previousAlertCount > 0 && data.total_alerts > previousAlertCount) {
      playAlert();
    }
    previousAlertCount = data.total_alerts;

    document.getElementById("total-alerts").textContent = data.total_alerts.toLocaleString();
    document.getElementById("ips-blocked").textContent = data.ips_blocked;
    document.getElementById("port-scans").textContent = data.port_scans;

    const breakdown = document.getElementById("breakdown");
    breakdown.innerHTML = "";
    for (const [type, count] of Object.entries(data.attack_breakdown)) {
      const cfg = ATTACK_COLORS[type] || { fill: "#8b949e", max: 100 };
      const pct = Math.min((count / cfg.max) * 100, 100).toFixed(1);
      breakdown.innerHTML += `
        <div class="bar-row">
          <span class="bar-label">${type.replace("Attack","").replace("Attempt","").replace("Packet","").trim()}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${cfg.fill}"></div></div>
          <span class="bar-count">${count.toLocaleString()}</span>
        </div>`;
    }

    const blockedBody = document.getElementById("blocked-table");
    blockedBody.innerHTML = "";
    for (const entry of data.blocked_ips) {
      const reasons = (entry.reasons || [])
        .map(r => `<span class="tag ${TAG_CLASS[r] || ''}">${r.replace(" Attack","").replace(" Attempt","")}</span>`)
        .join(" ");
      const geo = await getGeoIP(entry.ip);
      blockedBody.innerHTML += `
        <tr>
          <td style="font-family:monospace;color:#79c0ff">${entry.ip}</td>
          <td style="color:#8b949e;font-size:12px">${geo}</td>
          <td style="text-align:right">${reasons || "—"}</td>
        </tr>`;
    }

    const alertsBody = document.getElementById("alerts-body");
    alertsBody.innerHTML = "";
    for (const alert of data.recent_alerts.slice(0, 30)) {
      const tagClass = TAG_CLASS[alert.type] || "";
      alertsBody.innerHTML += `
        <tr>
          <td style="color:#8b949e;white-space:nowrap">${alert.time}</td>
          <td><span class="tag ${tagClass}">${alert.type}</span></td>
          <td style="font-family:monospace">${alert.src}</td>
          <td style="color:#8b949e">${alert.detail}</td>
        </tr>`;
    }

    updateTimestamp();
  } catch (e) {
    console.error("Failed to fetch stats:", e);
  }
}

fetchStats();
fetchTimeline();
setInterval(fetchStats, 3000);
setInterval(fetchTimeline, 3000);