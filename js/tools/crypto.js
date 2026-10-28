import { h, getJSON, card, asyncCard, kv, ext, pivot, grid, muted, badge, fmtNum, fmtDate } from '../util.js';
import { getKey, hasKey } from '../store.js';

const isBTC = a => /^(bc1[0-9a-z]{20,80}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(a);
const isETH = a => /^0x[0-9a-fA-F]{40}$/.test(a);
const btc = sats => (sats / 1e8).toFixed(8).replace(/\.?0+$/, '') + ' BTC';
const eth = wei => (Number(wei) / 1e18).toFixed(6).replace(/\.?0+$/, '') + ' ETH';

function bitcoin(addr) {
  return grid(
    asyncCard('bitcoin address', async () => {
      const r = await getJSON(`https://blockstream.info/api/address/${addr}`);
      if (!r.ok || !r.data) throw new Error(`explorer returned HTTP ${r.status}`);
      const d = r.data, cs = d.chain_stats, ms = d.mempool_stats;
      const balance = cs.funded_txo_sum - cs.spent_txo_sum;
      const txCount = cs.tx_count + ms.tx_count;
      return [
        kv([
          ['address', h('code', { class: 'wrap small' }, addr)],
          ['balance', h('strong', {}, btc(balance))],
          ['total received', btc(cs.funded_txo_sum)],
          ['total sent', btc(cs.spent_txo_sum)],
          ['transactions', fmtNum(txCount)],
          ['status', txCount ? badge('active', 'ok') : badge('never used', 'muted')],
        ]),
        h('div', { class: 'links' }, [
          ['mempool.space', `https://mempool.space/address/${addr}`],
          ['blockchair', `https://blockchair.com/bitcoin/address/${addr}`],
          ['OXT', `https://oxt.me/address/${addr}`],
          ['BlockCypher', `https://live.blockcypher.com/btc/address/${addr}/`],
        ].map(([n, u]) => ext(u, n))),
      ];
    }, { wide: true }),
    asyncCard('recent transactions', async () => {
      const r = await getJSON(`https://blockstream.info/api/address/${addr}/txs`);
      if (!r.ok || !Array.isArray(r.data)) throw new Error('could not load transactions');
      if (!r.data.length) return muted('no transactions.');
      return h('div', { class: 'tx-list' }, r.data.slice(0, 15).map(tx => {
        const time = tx.status?.block_time ? fmtDate(tx.status.block_time * 1000) : 'pending';
        const value = tx.vout.reduce((s, o) => s + o.value, 0);
        return h('div', { class: 'tx-item' },
          ext(`https://mempool.space/tx/${tx.txid}`, h('code', { class: 'small' }, tx.txid.slice(0, 20) + '…')),
          h('span', { class: 'muted small' }, `${btc(value)} · ${time}`));
      }));
    }, { wide: true }),
  );
}

function ethereum(addr) {
  if (!hasKey('etherscan')) {
    return grid(card('ethereum address', { wide: true },
      kv([['address', h('code', { class: 'wrap small' }, addr)]]),
      muted('Live Ethereum balance & transactions need a free Etherscan API key.'),
      h('p', {}, 'Add one in ', pivot('settings', 'keys', 'Settings'), ', or explore now:'),
      explorersETH(addr)));
  }
  return grid(
    asyncCard('ethereum address', async () => {
      const base = `https://api.etherscan.io/api?apikey=${getKey('etherscan')}`;
      const [bal, txr] = await Promise.all([
        getJSON(`${base}&module=account&action=balance&address=${addr}&tag=latest`),
        getJSON(`${base}&module=account&action=txlist&address=${addr}&page=1&offset=15&sort=desc`),
      ]);
      if (bal.data?.status === '0' && bal.data?.message !== 'OK') throw new Error(bal.data.result || 'Etherscan error');
      const txs = Array.isArray(txr.data?.result) ? txr.data.result : [];
      return [
        kv([
          ['address', h('code', { class: 'wrap small' }, addr)],
          ['balance', h('strong', {}, eth(bal.data.result))],
          ['transactions', txs.length ? `${txs.length}+ (recent)` : '0'],
        ]),
        explorersETH(addr),
        txs.length ? h('div', { class: 'tx-list' }, txs.map(tx => h('div', { class: 'tx-item' },
          ext(`https://etherscan.io/tx/${tx.hash}`, h('code', { class: 'small' }, tx.hash.slice(0, 20) + '…')),
          h('span', { class: 'muted small' },
            `${eth(tx.value)} · ${tx.from.toLowerCase() === addr.toLowerCase() ? 'out' : 'in'} · ${fmtDate(tx.timeStamp * 1000)}`)))) : null,
      ];
    }, { wide: true }),
  );
}

const explorersETH = addr => h('div', { class: 'links' }, [
  ['Etherscan', `https://etherscan.io/address/${addr}`],
  ['Blockchair', `https://blockchair.com/ethereum/address/${addr}`],
  ['Arkham', `https://platform.arkhamintelligence.com/explorer/address/${addr}`],
  ['DeBank', `https://debank.com/profile/${addr}`],
  ['Breadcrumbs', `https://www.breadcrumbs.app/reports/${addr}`],
].map(([n, u]) => ext(u, n)));

export default {
  id: 'crypto',
  label: 'wallet',
  placeholder: 'BTC or ETH address',
  intro: 'Look up balances, activity and transaction history on public blockchains, with links to the major chain-analysis explorers.',
  examples: ['1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'],

  run(raw) {
    const addr = raw.trim();
    if (!addr) throw new Error('enter a Bitcoin or Ethereum address');
    if (isBTC(addr)) return bitcoin(addr);
    if (isETH(addr)) return ethereum(addr);
    throw new Error('not a recognised BTC or ETH address');
  },
};
