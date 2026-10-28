// Background snowfall. Flakes drift with a wind that leans toward the cursor's side
// of the screen and swirl around the pointer when it comes near.

const canvas = document.getElementById('snow');
const ctx = canvas.getContext('2d');
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

const RADIUS = 170;
const pointer = { x: -1e4, y: -1e4, vx: 0, vy: 0, active: false };
let W = 0, H = 0, flakes = [], wind = 0, last = performance.now();

function flake(anywhere) {
  const z = Math.random(); // depth: 0 = far, 1 = near
  return {
    x: Math.random() * W,
    y: anywhere ? Math.random() * H : -8 - Math.random() * 40,
    z,
    r: 0.5 + z * z * 2.4,
    vx: 0,
    vy: 0,
    fall: 0.25 + z * 0.95,
    sway: Math.random() * Math.PI * 2,
    swaySpeed: 0.006 + Math.random() * 0.014,
    alpha: 0.18 + z * 0.7,
  };
}

function resize() {
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  W = innerWidth;
  H = innerHeight;
  canvas.width = Math.round(W * dpr);
  canvas.height = Math.round(H * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const target = Math.round(Math.min(320, (W * H) / 5200) * (reduced ? 0.3 : 1));
  while (flakes.length < target) flakes.push(flake(true));
  flakes.length = target;
}

function step(now) {
  const dt = Math.min(3, (now - last) / 16.67);
  last = now;

  // Wind leans toward whichever side the cursor is on; pointer speed decays.
  const targetWind = pointer.active ? (pointer.x / W - 0.5) * 1.2 : 0;
  wind += (targetWind - wind) * 0.02 * dt;
  pointer.vx *= 0.9;
  pointer.vy *= 0.9;

  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = '#fff';

  for (const f of flakes) {
    f.sway += f.swaySpeed * dt;
    let tx = Math.sin(f.sway) * (0.25 + f.z * 0.35) + wind * (0.4 + f.z);
    let ty = f.fall;

    if (pointer.active && !reduced) {
      const dx = pointer.x - f.x, dy = pointer.y - f.y;
      const d = Math.hypot(dx, dy);
      if (d < RADIUS && d > 0.5) {
        const s = 1 - d / RADIUS;
        const pull = s * (0.9 + f.z);
        // pull toward the pointer + swirl around it + get dragged along with it
        f.vx += ((dx / d) * pull * 0.09 + (-dy / d) * s * 0.16 + pointer.vx * s * 0.04) * dt;
        f.vy += ((dy / d) * pull * 0.09 + (dx / d) * s * 0.16 + pointer.vy * s * 0.04) * dt;
      }
    }

    f.vx += (tx - f.vx) * 0.035 * dt;
    f.vy += (ty - f.vy) * 0.035 * dt;
    f.x += f.vx * dt;
    f.y += f.vy * dt;

    if (f.y > H + 10) Object.assign(f, flake(false));
    else if (f.y < -60) f.y = H + 5;
    if (f.x > W + 10) f.x = -10;
    else if (f.x < -10) f.x = W + 10;

    ctx.globalAlpha = f.alpha;
    ctx.beginPath();
    ctx.arc(f.x, f.y, f.r, 0, Math.PI * 2);
    ctx.fill();
  }
  requestAnimationFrame(step);
}

addEventListener('pointermove', e => {
  if (pointer.active) {
    pointer.vx = pointer.vx * 0.5 + (e.clientX - pointer.x) * 0.5;
    pointer.vy = pointer.vy * 0.5 + (e.clientY - pointer.y) * 0.5;
  }
  pointer.x = e.clientX;
  pointer.y = e.clientY;
  pointer.active = true;
}, { passive: true });

const release = () => { pointer.active = false; };
document.addEventListener('pointerleave', release);
addEventListener('blur', release);
addEventListener('pointerup', e => { if (e.pointerType === 'touch') release(); });
addEventListener('resize', resize);

resize();
requestAnimationFrame(step);
