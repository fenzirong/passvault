// 可自定义的密码 / 口令生成器
import { randomBytes } from './util.js';

export const CHARSETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/',
};

export const AMBIGUOUS = '0O1lI|`\'"';

/** 常用英文短词表（用于易记口令，参考 EFF 短词表思路） */
export const WORDLIST = `able acid aged also area army away baby back ball band bank base bath bear beat beer bell belt bird blue boat body bone book boot born boss both bowl bulk burn bush busy cake call calm came camp card care case cash cast cell chat chip city club coal coat code cold come cook cool copy core cost crew crop dark data date dawn days dead deal dean dear debt deep deer desk dial diet disc disk does done door dose down draw drew drop drug dual duke dust duty each earn ease east easy edge exit face fact fail fair fall farm fast fate fear feed feel feet fell felt file fill film find fine fire firm fish five flat flow food foot ford form fort four free from fuel full fund gain game gate gave gear gene gift girl give glad goal goes gold golf gone good gray grew grow gulf hair half hall hand hang hard harm hate have head hear heat held hell help here hero high hill hire hold hole home hope host hour huge hung hunt hurt idea inch into iron item jack jane jean john join jump jury just keen keep kent kept kick kind king knee knew know lack lady laid lake land lane last late lawn lead leaf lean left less life lift like line link list live load loan lock logo long look loss lost love luck made mail main make male mall many mark mass matt meal mean meat meet menu mere mile milk mill mind mine miss mode mood moon more most move much must name navy near neck need news next nice nick nine none noon norm nose note noun okay once only onto open oral over pace pack page paid pain pair palm park part pass past path peak pick pink pipe plan play plot plug plus poll pool poor port post pull pure push race rail rain rank rare rate read real rear rely rent rest rice rich ride ring rise risk road rock role roll roof room root rope rose rule rush safe said sail sale salt same sand save seat seed seek seem seen self sell send sent sept ship shop shot show shut sick side sign silk sing sink site size skin slip slow snow soft soil sold sole some song soon sort soul spot star stay step stop such suit sure take tale talk tall tank task team tech tell tend term test text than that them then they thin this thus till time tiny told tone took tool tour town tree trip true turn twin type unit upon used user vary vast very view vote wage wait wake walk wall want ward warm wash wave ways weak wear week well went were west what when whom wide wife wild will wind wine wing wire wise wish with wood word wore work yard yeah year your zero zone`.split(
  /\s+/,
);

const AMBIGUOUS_SET = new Set(AMBIGUOUS);

/** 无偏随机整数 [0, max) */
export function randomInt(max) {
  if (max <= 0) throw new Error('随机范围必须大于 0');
  const limit = Math.floor(0xffffffff / max) * max;
  const buf = new Uint8Array(4);
  for (;;) {
    crypto.getRandomValues(buf);
    const v = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
    if (v < limit) return v % max;
  }
}

function pick(str) {
  return str[randomInt(str.length)];
}

function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/** 根据选项构建字符池 */
export function buildPool(opts = {}) {
  const {
    upper = true,
    lower = true,
    digits = true,
    symbols = true,
    excludeAmbiguous = true,
    customChars = '',
  } = opts;
  let pool = '';
  if (lower) pool += CHARSETS.lower;
  if (upper) pool += CHARSETS.upper;
  if (digits) pool += CHARSETS.digits;
  if (symbols) pool += CHARSETS.symbols;
  pool += String(customChars || '');
  if (excludeAmbiguous) {
    pool = Array.from(pool)
      .filter((c) => !AMBIGUOUS_SET.has(c))
      .join('');
  }
  // 去重
  pool = Array.from(new Set(pool)).join('');
  return pool;
}

/**
 * 生成随机密码
 * @param {object} opts length/upper/lower/digits/symbols/excludeAmbiguous/customChars/requireEach
 */
export function generatePassword(opts = {}) {
  const {
    length = 20,
    upper = true,
    lower = true,
    digits = true,
    symbols = true,
    excludeAmbiguous = true,
    customChars = '',
    requireEach = true,
  } = opts;

  const len = Math.max(4, Math.min(128, Math.floor(Number(length) || 20)));
  const pool = buildPool({ upper, lower, digits, symbols, excludeAmbiguous, customChars });
  if (!pool) throw new Error('请至少选择一种字符类型');

  const sets = [];
  const addSet = (base) => {
    let s = base;
    if (excludeAmbiguous) s = Array.from(s).filter((c) => !AMBIGUOUS_SET.has(c)).join('');
    if (s) sets.push(s);
  };
  if (lower) addSet(CHARSETS.lower);
  if (upper) addSet(CHARSETS.upper);
  if (digits) addSet(CHARSETS.digits);
  if (symbols) addSet(CHARSETS.symbols);

  const chars = [];
  if (requireEach) {
    for (const s of sets) {
      if (chars.length >= len) break;
      chars.push(pick(s));
    }
  }
  while (chars.length < len) chars.push(pick(pool));
  shuffle(chars);
  return chars.join('');
}

/** 生成易记口令（单词 + 分隔符） */
export function generatePassphrase(opts = {}) {
  const {
    words = 4,
    separator = '-',
    capitalize = true,
    addNumber = false,
    wordlist = WORDLIST,
  } = opts;
  const count = Math.max(2, Math.min(12, Math.floor(Number(words) || 4)));
  const parts = [];
  for (let i = 0; i < count; i++) {
    let w = wordlist[randomInt(wordlist.length)];
    if (capitalize) w = w[0].toUpperCase() + w.slice(1);
    parts.push(w);
  }
  if (addNumber) parts[parts.length - 1] += String(randomInt(100)).padStart(2, '0');
  return parts.join(separator);
}

/** 估算熵（比特） */
export function estimateEntropy(opts = {}) {
  if (opts.mode === 'passphrase') {
    const words = Math.max(2, Math.min(12, Number(opts.words) || 4));
    return Math.round(words * Math.log2(WORDLIST.length));
  }
  const pool = buildPool(opts);
  if (!pool) return 0;
  const len = Math.max(4, Math.min(128, Number(opts.length) || 20));
  return Math.round(len * Math.log2(pool.length));
}

/** 强度分级 */
export function strengthOf(bits) {
  if (bits < 40) return { level: 1, label: '很弱', color: '#e5484d' };
  if (bits < 60) return { level: 2, label: '较弱', color: '#f76b15' };
  if (bits < 80) return { level: 3, label: '中等', color: '#f5b301' };
  if (bits < 100) return { level: 4, label: '强', color: '#46a758' };
  return { level: 5, label: '很强', color: '#30a46c' };
}

/** 生成随机 PIN / 数字码 */
export function generatePin(length = 6) {
  const len = Math.max(4, Math.min(12, Number(length) || 6));
  let out = '';
  for (let i = 0; i < len; i++) out += String(randomInt(10));
  return out;
}

export { randomBytes };
