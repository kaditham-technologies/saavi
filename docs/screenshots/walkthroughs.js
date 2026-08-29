// Walkthrough rig: the moving half of shots.js. Same demo identity, same
// viewport, same flows the tutorial pages narrate — recorded rather than
// photographed, for the README and kaditham.ie/saavi/guide/.
//
// Run it exactly like shots.js, in mcr.microsoft.com/playwright with
// /app = this repo and /out = a work dir:
//
//   python3 -m http.server 4173 -d /app/dist &
//   npm i --no-save playwright && node walkthroughs.js
//
// Output: /out/video/{first-key,sealing}.webm. Turn those into the GIFs the
// README uses, and the MP4s the site uses, with ffmpeg:
//
//   ffmpeg -i in.webm -vf "fps=11,scale=880:-1:flags=lanczos,\
//     palettegen=max_colors=128:stats_mode=diff" pal.png
//   ffmpeg -i in.webm -i pal.png -lavfi "fps=11,scale=880:-1:flags=lanczos[x];\
//     [x][1:v]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" -loop 0 out.gif
//   ffmpeg -i in.webm -c:v libx264 -pix_fmt yuv420p -crf 23 -movflags +faststart -an out.mp4
//
// Regenerate after UI changes so the site's walkthroughs track the app.
const { chromium } = require('playwright');
const { mkdirSync, renameSync } = require('node:fs');

const PASS = 'lantern-orbit-velvet-canyon-ember-tide';
const EMAIL = 'anjali@example.ie';
const W = 1060, H = 680;

async function demoRing() {
  const openpgp = await import('/app/node_modules/openpgp/dist/node/openpgp.mjs');
  const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
    userIDs: [{ name: 'Anjali', email: EMAIL }],
    passphrase: PASS,
    type: 'ecc', curve: 'curve25519Legacy', format: 'armored',
  });
  return JSON.stringify({
    active: { publicKey, privateKey, created: new Date().toISOString(), revocationCertificate },
    retired: [],
  });
}

// A screen recording has no pointer, so every click would be invisible. This
// injects one the script can drive: window.__cursor(x, y) glides it, and
// window.__click() pulses it just before the real click lands.
function seedPage([ring, seed, email]) {
  localStorage.setItem('saavi-update-check', 'off');
  if (seed) localStorage.setItem('saavi-ring-' + email, ring);
  const install = () => {
    const c = document.createElement('div');
    c.id = '__cur';
    c.innerHTML = '<span class="p"></span><svg viewBox="0 0 20 26" width="20" height="26">'
      + '<path d="M2 1.5 L2 21 L7 16.5 L10.4 24 L13.6 22.6 L10.2 15.3 L17 15.2 Z" '
      + 'fill="#141018" stroke="#fff" stroke-width="1.4" stroke-linejoin="round"/></svg>';
    const s = document.createElement('style');
    s.textContent = '#__cur{position:fixed;left:0;top:0;width:20px;height:26px;pointer-events:none;'
      + 'z-index:2147483647;transform:translate(-60px,-60px);transition:transform .55s cubic-bezier(.4,0,.2,1);'
      + 'filter:drop-shadow(0 2px 3px rgba(0,0,0,.35))}'
      + '#__cur .p{position:absolute;left:-13px;top:-13px;width:44px;height:44px;border-radius:50%;'
      + 'background:rgba(109,17,209,.32);opacity:0}'
      + '#__cur.on .p{animation:__pulse .5s ease-out}'
      + '@keyframes __pulse{from{transform:scale(.25);opacity:.85}to{transform:scale(1);opacity:0}}';
    document.head.appendChild(s);
    document.body.appendChild(c);
    window.__cursor = (x, y) => { c.style.transform = `translate(${x}px,${y}px)`; };
    window.__click = () => { c.classList.remove('on'); void c.offsetWidth; c.classList.add('on'); };
  };
  if (document.body) install(); else document.addEventListener('DOMContentLoaded', install);
}

(async () => {
  mkdirSync('/out/video', { recursive: true });
  const ring = await demoRing();
  const browser = await chromium.launch();

  const session = async (seed) => {
    const ctx = await browser.newContext({
      viewport: { width: W, height: H }, deviceScaleFactor: 1,
      recordVideo: { dir: '/out/video', size: { width: W, height: H } },
    });
    await ctx.addInitScript(seedPage, [ring, seed, EMAIL]);
    const page = await ctx.newPage();
    await page.goto('http://localhost:4173/');
    await page.waitForSelector('#status');
    await page.waitForTimeout(1200);
    return { ctx, page };
  };

  const tap = async (page, sel) => {
    const loc = page.locator(sel);
    const b = await loc.boundingBox();
    await page.evaluate(([x, y]) => window.__cursor(x, y),
      [b.x + Math.min(b.width / 2, 110), b.y + b.height / 2]);
    await page.waitForTimeout(680);
    await page.evaluate(() => window.__click());
    await page.waitForTimeout(160);
    await loc.click();
    await page.waitForTimeout(260);
  };
  const type = async (page, sel, text, delay = 50) => {
    await tap(page, sel);
    await page.locator(sel).pressSequentially(text, { delay });
    await page.waitForTimeout(500);
  };
  const finish = async (ctx, page, name) => {
    const src = await page.video().path();
    await ctx.close();
    renameSync(src, `/out/video/${name}.webm`);
    console.log('wrote', name);
  };

  // 1. Your first key — from an empty keyring to a key in the list.
  {
    const { ctx, page } = await session(false);
    await page.waitForTimeout(1500);
    await tap(page, '#rows button.primary');
    await page.waitForTimeout(700);
    await type(page, '#m-name', 'Anjali');
    await type(page, '#m-email', EMAIL);
    await page.waitForTimeout(1700);          // long enough to read the six words
    await tap(page, '#m-suggest');            // they are yours to reroll
    await page.waitForTimeout(2500);
    await tap(page, '#m-go');
    await page.waitForSelector('#f-done:not([hidden])', { timeout: 30000 });
    await page.waitForTimeout(3200);          // the fingerprint
    await tap(page, '#m-go');
    await page.waitForSelector('.row');
    await page.waitForTimeout(2600);
    await finish(ctx, page, 'first-key');
  }

  // 2. Sealing a letter — seal it, then read it back with its verdict.
  {
    const { ctx, page } = await session(true);
    await tap(page, '#tab-seal');
    await page.waitForTimeout(500);
    await type(page, '#seal-to', EMAIL);
    await tap(page, '#seal-sign');
    await page.selectOption('#seal-sign', EMAIL);
    await page.waitForTimeout(600);
    await type(page, '#seal-in', 'Meet me at the harbour at six — bring the good coffee.\n\n— A', 42);
    await tap(page, '#seal-enc');
    await page.waitForSelector('#m-pass', { timeout: 15000 });
    await page.waitForTimeout(700);
    await type(page, '#m-pass', PASS, 24);
    await tap(page, '#m-go');
    await page.waitForSelector('#seal-out', { timeout: 25000 });
    await page.evaluate(() => document.getElementById('seal-out-fld')
      .scrollIntoView({ block: 'end', behavior: 'smooth' }));
    await page.waitForTimeout(3200);          // the armored letter

    const armor = await page.inputValue('#seal-out');
    await tap(page, '#seal-in');
    await page.fill('#seal-in', armor);
    await page.waitForTimeout(900);
    await tap(page, '#seal-dec');
    await page.waitForSelector('#seal-sig:not([hidden])', { timeout: 20000 });
    await page.evaluate(() => document.getElementById('seal-sig')
      .scrollIntoView({ block: 'center', behavior: 'smooth' }));
    await page.waitForTimeout(3600);          // the signature verdict
    await finish(ctx, page, 'sealing');
  }

  await browser.close();
  console.log('done');
})().catch((e) => { console.error(e); process.exit(1); });
