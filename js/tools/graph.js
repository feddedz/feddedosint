import { h, card, muted, badge, copyBtn } from '../util.js';
import { graph, clearGraph } from '../store.js';

// Short label for a node: the value, trimmed.
const shortLabel = v => (v.length > 22 ? v.slice(0, 20) + '…' : v);

function simulate(canvas, data, onPick) {
  const ctx = canvas.getContext('2d');
  const light = document.documentElement.getAttribute('data-theme') === 'light';
  const COL = light
    ? { edge: 'rgba(0,0,0,0.18)', node: 'rgba(20,20,25,0.9)', nodeOn: '#000', ring: 'rgba(255,255,255,0.7)', label: 'rgba(60,60,70,0.9)', labelOn: '#000' }
    : { edge: 'rgba(255,255,255,0.14)', node: 'rgba(230,230,235,0.9)', nodeOn: '#fff', ring: 'rgba(0,0,0,0.6)', label: 'rgba(180,180,190,0.9)', labelOn: '#fff' };
  const ids = Object.keys(data.nodes);
  const idx = Object.fromEntries(ids.map((id, i) => [id, i]));
  let W = 0, H = 0;

  // Seed positions in a loose circle so the layout unfolds nicely.
  const seedR = 90 + ids.length * 14;
  const nodes = ids.map((id, i) => {
    const a = (i / ids.length) * Math.PI * 2;
    return { ...data.nodes[id], x: Math.cos(a) * seedR, y: Math.sin(a) * seedR, vx: 0, vy: 0 };
  });
  const edges = data.edges.filter(e => idx[e.from] != null && idx[e.to] != null)
    .map(e => ({ a: idx[e.from], b: idx[e.to] }));
  const degree = nodes.map(() => 0);
  for (const e of edges) { degree[e.a]++; degree[e.b]++; }

  const dpr = () => Math.min(devicePixelRatio || 1, 2);
  function resize() {
    W = canvas.clientWidth; H = canvas.clientHeight;
    canvas.width = W * dpr(); canvas.height = H * dpr();
    ctx.setTransform(dpr(), 0, 0, dpr(), 0, 0);
  }

  let drag = null, hover = null;
  const pan = { x: 0, y: 0 };
  const toWorld = (mx, my) => ({ x: mx - W / 2 - pan.x, y: my - H / 2 - pan.y });

  function pick(mx, my) {
    const p = toWorld(mx, my);
    let best = null, bd = 18 * 18;
    for (const n of nodes) {
      const d = (n.x - p.x) ** 2 + (n.y - p.y) ** 2;
      if (d < bd) { bd = d; best = n; }
    }
    return best;
  }

  canvas.onpointermove = e => {
    const r = canvas.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    if (drag) { const p = toWorld(mx, my); drag.node.x = p.x; drag.node.y = p.y; drag.node.fixed = true; drag.moved = true; }
    else { hover = pick(mx, my); canvas.style.cursor = hover ? 'pointer' : 'grab'; }
  };
  canvas.onpointerdown = e => {
    const r = canvas.getBoundingClientRect();
    const n = pick(e.clientX - r.left, e.clientY - r.top);
    drag = n ? { node: n, moved: false } : { pan: true, sx: e.clientX - pan.x, sy: e.clientY - pan.y };
    canvas.setPointerCapture(e.pointerId);
  };
  canvas.onpointerup = e => {
    if (drag?.node && !drag.moved) onPick(drag.node);
    drag = null;
  };
  window.addEventListener('pointermove', panMove);
  function panMove(e) { if (drag?.pan) { pan.x = e.clientX - drag.sx; pan.y = e.clientY - drag.sy; } }

  resize();
  const ro = new ResizeObserver(resize);
  ro.observe(canvas);

  function frame() {
    if (!canvas.isConnected) { ro.disconnect(); window.removeEventListener('pointermove', panMove); return; }
    // forces
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy || 0.01;
        const f = 9000 / d2;
        const d = Math.sqrt(d2);
        a.vx += (dx / d) * f; a.vy += (dy / d) * f;
        b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
      }
      a.vx -= a.x * 0.006; a.vy -= a.y * 0.006; // gentle pull to centre
    }
    for (const e of edges) {
      const a = nodes[e.a], b = nodes[e.b];
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.hypot(dx, dy) || 0.01;
      const f = (d - 120) * 0.02;
      a.vx += (dx / d) * f; a.vy += (dy / d) * f;
      b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
    }
    for (const n of nodes) {
      if (n.fixed) { n.vx = n.vy = 0; continue; }
      n.vx *= 0.82; n.vy *= 0.82;
      n.x += Math.max(-8, Math.min(8, n.vx));
      n.y += Math.max(-8, Math.min(8, n.vy));
    }

    // draw
    ctx.clearRect(0, 0, W, H);
    ctx.save();
    ctx.translate(W / 2 + pan.x, H / 2 + pan.y);
    ctx.strokeStyle = COL.edge;
    ctx.lineWidth = 1;
    for (const e of edges) {
      ctx.beginPath();
      ctx.moveTo(nodes[e.a].x, nodes[e.a].y);
      ctx.lineTo(nodes[e.b].x, nodes[e.b].y);
      ctx.stroke();
    }
    ctx.font = '11px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const r = 5 + Math.min(degree[i], 6);
      const on = n === hover;
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.fillStyle = on ? COL.nodeOn : COL.node;
      ctx.fill();
      ctx.lineWidth = 2;
      ctx.strokeStyle = COL.ring;
      ctx.stroke();
      ctx.fillStyle = on ? COL.labelOn : COL.label;
      ctx.fillText(`${n.tool}·${shortLabel(n.value)}`, n.x, n.y + r + 13);
    }
    ctx.restore();
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

export default {
  id: 'graph',
  label: 'graph',
  placeholder: 'the investigation graph builds itself as you search',
  intro: 'A live map of everything you have looked at. Each search adds a node; pivoting between results draws the links. Drag to arrange, click a node to reopen it.',
  examples: [],
  allowEmpty: true,
  noInput: true,

  run() {
    const data = graph();
    const n = Object.keys(data.nodes).length;
    if (!n) {
      return card('nothing yet', { wide: true },
        muted('Run a few searches and pivot between results (click the linked IPs, domains, emails and handles). Every entity you touch becomes a node here, and the connections are drawn automatically.'));
    }

    const canvas = h('canvas', { class: 'graphcanvas' });
    const exportJSON = () => JSON.stringify(data, null, 2);
    const dl = h('button', { class: 'mini', type: 'button' }, 'export json');
    dl.onclick = () => {
      const blob = new Blob([exportJSON()], { type: 'application/json' });
      const a = h('a', { href: URL.createObjectURL(blob), download: 'feddedosint-graph.json' });
      a.click();
    };
    const clear = h('button', { class: 'mini ghost', type: 'button' }, 'clear graph');
    clear.onclick = () => { clearGraph(); location.hash = '#graph/'; location.reload(); };

    const wrap = card('investigation graph', {
      wide: true,
      actions: [badge(`${n} nodes · ${data.edges.length} links`), copyBtn(exportJSON, 'copy'), dl, clear],
    }, h('div', { class: 'graphwrap' }, canvas),
      muted('drag nodes to arrange · drag the background to pan · click a node to reopen that lookup'));

    // Start the simulation once the canvas has a measured size.
    requestAnimationFrame(() => simulate(canvas, data, node => { location.hash = `#${node.tool}/${encodeURIComponent(node.value)}`; }));
    return wrap;
  },
};
