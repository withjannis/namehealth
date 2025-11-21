/* Sidebar controls */
var mySidebar = document.getElementById("mySidebar");
var overlayBg = document.getElementById("myOverlay");

// initialize sidebar state early (keeps layout stable)
(function(){
  // if viewport wide, keep sidebar considered present
  if (window.innerWidth > 900) {
    document.body.classList.add('has-sidebar');
    // ensure sidebar is visible on wide screens
    if (mySidebar) mySidebar.style.display = 'block';
  } else {
    // small screens: hide sidebar initially
    if (mySidebar) mySidebar.style.display = 'none';
    if (overlayBg) overlayBg.style.display = 'none';
  }
})();

function w3_open() {
  // mobile: show overlay + sidebar
  if (window.innerWidth <= 900) {
    if (mySidebar) mySidebar.style.display = 'block';
    if (overlayBg) overlayBg.style.display = 'block';
    if (mySidebar) mySidebar.setAttribute('aria-hidden', 'false');
    return;
  }

  // desktop: toggle presence class to collapse/expand sidebar space
  if (document.body.classList.contains('has-sidebar')) {
    document.body.classList.remove('has-sidebar');
  } else {
    document.body.classList.add('has-sidebar');
  }
}

function w3_close() {
  // mobile: hide sidebar + overlay
  if (mySidebar) mySidebar.style.display = 'none';
  if (overlayBg) overlayBg.style.display = 'none';
  if (mySidebar) mySidebar.setAttribute('aria-hidden', 'true');
}

// close sidebar/overlay when resizing to avoid stuck states
window.addEventListener('resize', function() {
  if (window.innerWidth > 900) {
    // on wide screens make sure overlay hidden and sidebar visible
    if (overlayBg) overlayBg.style.display = 'none';
    if (mySidebar) mySidebar.style.display = 'block';
    document.body.classList.add('has-sidebar');
  } else {
    // on narrow screens hide sidebar initially (until user opens it)
    if (mySidebar) mySidebar.style.display = 'none';
    if (overlayBg) overlayBg.style.display = 'none';
  }
});

/* human readable time difference */
function timeDifference(previous) {
    var current = Date.now();
    var msPerMinute = 60 * 1000;
    var msPerHour = msPerMinute * 60;
    var msPerDay = msPerHour * 24;
    var msPerMonth = msPerDay * 30;
    var msPerYear = msPerDay * 365;
    var elapsed = current - (previous * 1000);
    if (elapsed < msPerMinute) return Math.round(elapsed/1000) + ' seconds ago';
    if (elapsed < msPerHour) return Math.round(elapsed/msPerMinute) + ' minutes ago';
    if (elapsed < msPerDay) return Math.round(elapsed/msPerHour) + ' hours ago';
    if (elapsed < msPerMonth) return '~' + Math.round(elapsed/msPerDay) + ' days ago';
    if (elapsed < msPerYear) return '~' + Math.round(elapsed/msPerMonth) + ' months ago';
    return '~' + Math.round(elapsed/msPerYear ) + ' years ago';
}

/* helper: truncate string to n chars (adds ellipsis) */
function truncateString(s, n) {
  if (s === null || s === undefined) return '';
  const str = String(s);
  if (str.length <= n) return str;
  return str.slice(0, n - 1) + '…';
}

/* helper to render a single data key/value (with truncation + copy) */
function elDataItem(label, data) {
  const d = document.createElement('div');
  d.className = 'data-item';
  key_sort_list = {
    "SOA": ["mname", "rname", "serial", "expire", "refresh", "retry", "expire", "minimum",],
    "A": ["addr",],
    "AAAA": ["addr",],
    "MX": ["preference", "exchange",],
    "DS": ["key_tag", "algorithm", "digest_type", "digest",],
    "DNSKEY": ["algorithm", "flags", "protocol", "public_key",],
    "TXT": ["text",],
  }
  const description = key_sort_list[label]
    .filter(key => key in data)
    .join(' ');

  const values = key_sort_list[label]
    .filter(key => key in data)
    .map(key => data[key])
    .join(' ');

  d.innerHTML = `
    <div style="font-size:0.85rem;color:var(--muted)">
    <strong>${escapeHtml(label)}</strong>
    (${escapeHtml(description)})
    </div>
    <div style="margin-top:6px;display:flex;align-items:center;gap:6px">
      <span class="value" style="overflow: hidden; text-overflow: ellipsis;">${escapeHtml(values)}</span>
      <button class="copy-btn" title="Copy full value">Copy</button>
    </div>
  `;

  // attach copy behaviour if present
  const btn = d.querySelector('.copy-btn');
  if (btn) {
    btn.addEventListener('click', async (ev) => {
      ev.preventDefault();
      try {
        await navigator.clipboard.writeText(values);
        const old = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(() => btn.textContent = old, 500);
      } catch (err) {
        btn.textContent = 'Err';
        setTimeout(() => btn.textContent = 'Copy', 500);
      }
    });
  }

  return d;
}

/* small helper to escape text for use in title/textContent when injecting HTML */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/* render record without dumping JSON */
function renderRecord(rec) {
  const card = document.createElement('div');
  card.className = 'record-card';

  const meta = document.createElement('div');
  meta.className = 'record-meta';
  meta.innerHTML = `<div><strong>${rec[0].type}</strong></div>
                    <div>${rec[0].name}</div>
                    <div>ttl: ${rec[0].ttl}</div>
                    <div>${rec[0].class}</div>`;

  card.appendChild(meta);

  const dataRow = document.createElement('div');
  dataRow.className = 'record-data';


  // type-specific rendering
  for (i in rec) {
    const rtype = (rec[i].type).toUpperCase();
    const data = rec[i].data;
    dataRow.appendChild(elDataItem(rtype, data));
  }
  card.appendChild(dataRow);
  return card;
}

function clearData() {
  // Clear previous UI data immediately
  document.getElementById("x-domain-name").textContent = 'Search for domain...';
  document.getElementById("x-fqdn").textContent = '';
  document.getElementById("x-timestamp").textContent = '';
  document.getElementById("x-ns").textContent = '';
  document.getElementById("x-recordtype").textContent = '';
  document.getElementById("x-subtitle").textContent = 'Nameserver • Type';
}

async function getData(domain, record_type) {
  const url = `/api/v1/domain/${encodeURIComponent(domain)}/${encodeURIComponent(record_type)}`;

  const recordsEl = document.getElementById("x-records");

  // Show loading state
  recordsEl.innerHTML = '<div class="w3-panel" style="background:transparent;color:var(--muted)">Loading…</div>';

  try {
    // HEAD check
    const headResp = await fetch(url, { method: "HEAD" });
    if (headResp.status === 204) {
      recordsEl.innerHTML = `<div class="w3-panel">No data found for ${domain} (${record_type}) in the database. It may not have been probed yet.</div>`;
      clearData();
      return;
    }

    // GET the actual data
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const result = await response.json();

    document.getElementById("x-domain-name").textContent = result.fqdn;
    document.getElementById("x-fqdn").textContent = result.fqdn;
    document.getElementById("x-timestamp").textContent = timeDifference(result.timestamp);
    document.getElementById("x-ns").textContent = result.ns;
    document.getElementById("x-recordtype").textContent = result.type;
    document.getElementById("x-subtitle").textContent = `${result.ns} — ${result.type}`;

    recordsEl.innerHTML = '';
    const list = Array.isArray(result.records) ? result.records : [];

    if (list.length === 0) {
      recordsEl.innerHTML = '<div class="w3-panel">No records, Nameserver answered with empty response!</div>';
      return;
    }

    recordsEl.appendChild(renderRecord(list));

  } catch (error) {
    console.error(error);
    recordsEl.innerHTML = `<div class="w3-panel w3-red">Error fetching data: ${error.message}</div>`;
  }
}

async function updateNav(pageElement) {
  navElements = ["x-navabout", "x-navrecords"];
  for (x of navElements) {
    xEl = document.getElementById(x);
    if(pageElement == x){
      xEl.classList.add("w3-blue")
    } else {
      xEl.classList.remove("w3-blue")
    }
  }
}

async function aboutPage() {
  updateNav("x-navabout");
  var ElAbout = document.getElementById('x-about');
  if (ElAbout) ElAbout.style.display = 'block';

  const response = await fetch("/api/v1/about");
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const result = await response.json();

  document.getElementById("x-about").innerHTML = result.about;
}

async function recordsPage() {
  updateNav("x-navrecords");
  var ElRecordsSearch = document.getElementById('x-records-search');
  var ElRecordsSubtitle = document.getElementById('x-records-subtitle');
  var ElRecords = document.getElementById('x-records');
  if (ElRecordsSearch) {
    ElRecordsSearch.style.display = 'block';
  }
  if (ElRecords) {
    ElRecords.style.display = "block";
  }
  if (ElRecordsSubtitle) {
    ElRecordsSubtitle.style.display = "block";
  }

  const form = document.getElementById('x-records-search-form');

  const domainInput = document.getElementById('x-records-search-domain');
  const rtypeSelect = document.getElementById('x-records-search-rtype');

  const params = new URLSearchParams(document.location.search);
  const initialDomain = (params.get('domain') || 'example.com').toLowerCase();
  const initialRtype = (params.get('rtype') || 'A').toUpperCase();

  domainInput.value = initialDomain;
  rtypeSelect.value = initialRtype;

  getData(initialDomain, initialRtype);

  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const domain = (domainInput.value.trim() || 'example.com').toLowerCase();
    const rtype = (rtypeSelect.value || 'A').toUpperCase();

    const newParams = new URLSearchParams();
    newParams.set('domain', domain);
    newParams.set('rtype', rtype);
    history.replaceState(null, '', `${location.pathname}?${newParams.toString()}`);

    getData(domain, rtype);
  });
}

/* search form wiring */
(function() {

  console.log(location.pathname)
  if (location.pathname == "/") {
    console.log("path is /");
    window.location.href = '/view/records';

  } else if (location.pathname == "/view") {
    console.log("path is /view");
    window.location.href = '/view/records';

  } else if (location.pathname == "/view/about") {
    console.log("path is /view/about");
    aboutPage();

  } else if (location.pathname == "/view/records") {
    recordsPage();
  }

})();

async function renderDnssecChain(){
  const url = "/api/v1/dnssec.json"

  const response = await fetch(url);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const result = await response.json();

  const recordsEl = document.getElementById("x-dnssecchain");

  for (const i in result.data) {
    console.log(result.data[i].fqdn);

    const card = document.createElement('div');
    card.className = 'record-card';

    const meta = document.createElement('div');
    meta.className = 'record-meta';
    meta.innerHTML = `<div><strong>${result.data[i].fqdn}</strong></div>`;

    card.appendChild(meta);

    const dataRow = document.createElement('div');
    dataRow.className = 'record-data';
    for (const j in result.data[i].DS) {

      dataRow.appendChild(elDataItem("DS", result.data[i].DS[j]));

      card.appendChild(dataRow);
      recordsEl.appendChild(card);
    }

    for (const j in result.data[i].DNSKEYS) {
      dataRow.appendChild(elDataItem("DNSKEY", result.data[i].DNSKEYS[j]));

      card.appendChild(dataRow);
      recordsEl.appendChild(card);
    }
  }
}
//renderDnssecChain();
