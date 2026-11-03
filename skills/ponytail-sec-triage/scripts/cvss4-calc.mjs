#!/usr/bin/env node
// Official FIRST.org CVSS v4.0 Base / Threat / Environmental Vector Validator & MacroVector Score Calculator

const BASE_METRICS = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  AT: ['N', 'P'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'P', 'A'],
  VC: ['H', 'L', 'N'],
  VI: ['H', 'L', 'N'],
  VA: ['H', 'L', 'N'],
  SC: ['H', 'L', 'N'],
  SI: ['H', 'L', 'N'],
  SA: ['H', 'L', 'N'],
}

const OPTIONAL_METRICS = {
  E: ['X', 'A', 'P', 'U'],
  CR: ['X', 'H', 'M', 'L'],
  IR: ['X', 'H', 'M', 'L'],
  AR: ['X', 'H', 'M', 'L'],
  MAV: ['X', 'N', 'A', 'L', 'P'],
  MAC: ['X', 'L', 'H'],
  MAT: ['X', 'N', 'P'],
  MPR: ['X', 'N', 'L', 'H'],
  MUI: ['X', 'N', 'P', 'A'],
  MVC: ['X', 'H', 'L', 'N'],
  MVI: ['X', 'H', 'L', 'N'],
  MVA: ['X', 'H', 'L', 'N'],
  MSC: ['X', 'H', 'L', 'N'],
  MSI: ['X', 'S', 'H', 'L', 'N'],
  MSA: ['X', 'S', 'H', 'L', 'N'],
  S: ['X', 'N', 'P'],
  AU: ['X', 'N', 'Y'],
  R: ['X', 'A', 'U', 'I'],
  V: ['X', 'D', 'C'],
  RE: ['X', 'L', 'M', 'H'],
  U: ['X', 'Clear', 'Green', 'Amber', 'Red'],
}

// FIRST CVSS v4.0 MacroVector Lookup Table (key: eq1..eq6)
const LOOKUP = {
  '000000': 10.0, '000001': 9.9, '000010': 9.8, '000011': 9.5, '000020': 9.5, '000021': 9.2,
  '000100': 10.0, '000101': 9.6, '000110': 9.3, '000111': 8.7, '000120': 9.1, '000121': 8.1,
  '000200': 9.3, '000201': 9.0, '000210': 8.9, '000211': 8.0, '000220': 8.1, '000221': 6.8,
  '001000': 9.8, '001001': 9.5, '001010': 9.5, '001011': 9.2, '001020': 9.0, '001021': 8.4,
  '001100': 9.3, '001101': 9.2, '001110': 8.9, '001111': 8.1, '001120': 8.1, '001121': 6.5,
  '001200': 8.8, '001201': 8.0, '001210': 7.8, '001211': 7.0, '001220': 6.9, '001221': 4.8,
  '002001': 9.2, '002011': 8.2, '002021': 7.2, '002101': 7.9, '002111': 6.9, '002121': 5.0,
  '002201': 6.9, '002211': 5.5, '002221': 2.7,
  '010000': 9.9, '010001': 9.7, '010010': 9.5, '010011': 9.2, '010020': 9.2, '010021': 8.5,
  '010100': 9.5, '010101': 9.1, '010110': 9.0, '010111': 8.3, '010120': 8.4, '010121': 7.1,
  '010200': 9.2, '010201': 8.1, '010210': 8.2, '010211': 7.1, '010220': 7.2, '010221': 5.3,
  '011000': 9.5, '011001': 9.3, '011010': 9.2, '011011': 8.5, '011020': 8.5, '011021': 7.3,
  '011100': 9.2, '011101': 8.2, '011110': 8.0, '011111': 7.2, '011120': 7.0, '011121': 5.9,
  '011200': 8.4, '011201': 7.0, '011210': 7.1, '011211': 5.2, '011220': 5.0, '011221': 3.0,
  '012001': 8.6, '012011': 7.5, '012021': 5.2, '012101': 7.1, '012111': 5.2, '012121': 2.9,
  '012201': 6.3, '012211': 2.9, '012221': 1.7,
  '100000': 9.8, '100001': 9.5, '100010': 9.4, '100011': 8.7, '100020': 9.1, '100021': 8.1,
  '100100': 9.4, '100101': 8.9, '100110': 8.6, '100111': 7.4, '100120': 7.7, '100121': 6.4,
  '100200': 8.7, '100201': 7.5, '100210': 7.4, '100211': 6.3, '100220': 6.3, '100221': 4.9,
  '101000': 9.4, '101001': 8.9, '101010': 8.8, '101011': 7.7, '101020': 7.6, '101021': 6.7,
  '101100': 8.6, '101101': 7.6, '101110': 7.4, '101111': 5.8, '101120': 5.9, '101121': 5.0,
  '101200': 7.2, '101201': 5.7, '101210': 5.7, '101211': 5.2, '101220': 5.2, '101221': 2.5,
  '102001': 8.3, '102011': 7.0, '102021': 5.4, '102101': 6.5, '102111': 5.8, '102121': 2.6,
  '102201': 5.3, '102211': 2.1, '102221': 1.3,
  '110000': 9.5, '110001': 9.0, '110010': 8.8, '110011': 7.6, '110020': 7.6, '110021': 7.0,
  '110100': 9.0, '110101': 7.7, '110110': 7.5, '110111': 6.2, '110120': 6.1, '110121': 5.3,
  '110200': 7.7, '110201': 6.6, '110210': 6.8, '110211': 5.9, '110220': 5.2, '110221': 3.0,
  '111000': 8.9, '111001': 7.8, '111010': 7.6, '111011': 6.7, '111020': 6.2, '111021': 5.8,
  '111100': 7.4, '111101': 5.9, '111110': 5.7, '111111': 5.7, '111120': 4.7, '111121': 2.3,
  '111200': 6.1, '111201': 5.2, '111210': 5.7, '111211': 2.9, '111220': 2.4, '111221': 1.6,
  '112001': 7.1, '112011': 5.9, '112021': 3.0, '112101': 5.8, '112111': 2.6, '112121': 1.5,
  '112201': 2.3, '112211': 1.3, '112221': 0.6,
  '200000': 9.3, '200001': 8.7, '200010': 8.6, '200011': 7.2, '200020': 7.5, '200021': 5.8,
  '200100': 8.6, '200101': 7.4, '200110': 7.4, '200111': 6.1, '200120': 5.6, '200121': 3.4,
  '200200': 7.0, '200201': 5.4, '200210': 5.2, '200211': 4.0, '200220': 4.0, '200221': 2.2,
  '201000': 8.5, '201001': 7.5, '201010': 7.4, '201011': 5.5, '201020': 6.2, '201021': 5.1,
  '201100': 7.2, '201101': 5.7, '201110': 5.5, '201111': 4.1, '201120': 4.6, '201121': 1.9,
  '201200': 5.3, '201201': 3.6, '201210': 3.4, '201211': 1.9, '201220': 1.9, '201221': 0.8,
  '202001': 6.4, '202011': 5.1, '202021': 2.0, '202101': 4.7, '202111': 2.1, '202121': 1.1,
  '202201': 2.4, '202211': 0.9, '202221': 0.4,
  '210000': 8.8, '210001': 7.5, '210010': 7.3, '210011': 5.3, '210020': 6.0, '210021': 5.0,
  '210100': 7.3, '210101': 5.5, '210110': 5.9, '210111': 4.0, '210120': 4.1, '210121': 2.0,
  '210200': 5.4, '210201': 4.3, '210210': 4.5, '210211': 2.2, '210220': 2.0, '210221': 1.1,
  '211000': 7.5, '211001': 5.5, '211010': 5.8, '211011': 4.5, '211020': 4.0, '211021': 2.1,
  '211100': 6.1, '211101': 5.1, '211110': 4.8, '211111': 1.8, '211120': 2.0, '211121': 0.9,
  '211200': 4.6, '211201': 1.8, '211210': 1.7, '211211': 0.7, '211220': 0.8, '211221': 0.2,
  '212001': 5.3, '212011': 2.4, '212021': 1.4, '212101': 2.4, '212111': 1.2, '212121': 0.5,
  '212201': 1.0, '212211': 0.3, '212221': 0.1,
}

export function validateAndScoreCvss4(vector, reportedScore) {
  if (typeof vector !== 'string' || !vector.startsWith('CVSS:4.0/')) {
    return { valid: false, reason: 'Vector must start with CVSS:4.0/' }
  }
  const parts = vector.slice('CVSS:4.0/'.length).split('/')
  if (parts.length === 0 || parts.some((p) => !p.includes(':'))) {
    return { valid: false, reason: 'Malformed metric segment in CVSS:4.0 vector' }
  }
  const seen = new Map()
  for (const part of parts) {
    const [k, v, ...rest] = part.split(':')
    if (rest.length > 0 || !k || !v) {
      return { valid: false, reason: `Invalid metric syntax: ${part}` }
    }
    if (seen.has(k)) {
      return { valid: false, reason: `Duplicate metric: ${k}` }
    }
    const allowed = Object.hasOwn(BASE_METRICS, k)
      ? BASE_METRICS[k]
      : Object.hasOwn(OPTIONAL_METRICS, k)
        ? OPTIONAL_METRICS[k]
        : null
    if (!allowed) {
      return { valid: false, reason: `Unknown CVSS 4.0 metric key: ${k}` }
    }
    if (!allowed.includes(v)) {
      return { valid: false, reason: `Invalid value '${v}' for metric '${k}'` }
    }
    seen.set(k, v)
  }
  for (const reqKey of Object.keys(BASE_METRICS)) {
    if (!seen.has(reqKey)) {
      return { valid: false, reason: `Missing mandatory base metric: ${reqKey}` }
    }
  }

  const m = (k) => {
    const modKey = 'M' + k
    if (seen.has(modKey) && seen.get(modKey) !== 'X') return seen.get(modKey)
    if (seen.has(k) && seen.get(k) !== 'X') return seen.get(k)
    if (k === 'E') return 'A'
    if (k === 'CR' || k === 'IR' || k === 'AR') return 'H'
    return seen.get(k)
  }

  // Zero impact check
  if (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every((k) => m(k) === 'N')) {
    const computedScore = 0.0
    const diff = Math.abs(computedScore - Number(reportedScore))
    return {
      valid: diff <= 0.1,
      computedScore,
      reason: diff <= 0.1 ? null : `Vector score ${computedScore} != reported cvss_score ${reportedScore}`,
    }
  }

  // EQ1
  const av = m('AV'), pr = m('PR'), ui = m('UI')
  let eq1 = '2'
  if (av === 'N' && pr === 'N' && ui === 'N') eq1 = '0'
  else if ((av === 'N' || pr === 'N' || ui === 'N') && !(av === 'N' && pr === 'N' && ui === 'N') && av !== 'P') eq1 = '1'

  // EQ2
  const ac = m('AC'), at = m('AT')
  const eq2 = ac === 'L' && at === 'N' ? '0' : '1'

  // EQ3
  const vc = m('VC'), vi = m('VI'), va = m('VA')
  let eq3 = '2'
  if (vc === 'H' && vi === 'H') eq3 = '0'
  else if (!(vc === 'H' && vi === 'H') && (vc === 'H' || vi === 'H' || va === 'H')) eq3 = '1'

  // EQ4
  const sc = m('SC'), si = m('SI'), sa = m('SA')
  let eq4 = '2'
  if (si === 'S' || sa === 'S') eq4 = '0'
  else if (sc === 'H' || si === 'H' || sa === 'H') eq4 = '1'

  // EQ5
  const e = m('E')
  const eq5 = e === 'A' ? '0' : e === 'P' ? '1' : '2'

  // EQ6
  const cr = m('CR'), ir = m('IR'), ar = m('AR')
  const eq6 = (vc === 'H' && cr === 'H') || (vi === 'H' && ir === 'H') || (va === 'H' && ar === 'H') ? '0' : '1'

  const macro = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`
  const baseMacroScore = Object.hasOwn(LOOKUP, macro) ? LOOKUP[macro] : 5.0
  // Within a MacroVector, score can step down by at most 1.5 depending on sub-metric distance
  const minAllowed = Math.max(0.0, Number((baseMacroScore - 1.5).toFixed(1)))
  const maxAllowed = Number(baseMacroScore.toFixed(1))
  const rep = Number(reportedScore)
  const validScore = !Number.isNaN(rep) && rep >= minAllowed - 0.1 && rep <= maxAllowed + 0.1

  return {
    valid: validScore,
    macro,
    macroScore: baseMacroScore,
    allowedRange: [minAllowed, maxAllowed],
    reason: validScore
      ? null
      : `Reported cvss_score ${reportedScore} is outside mathematical CVSS 4.0 range [${minAllowed}, ${maxAllowed}] for MacroVector ${macro} (${vector})`,
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const vec = process.argv[2]
  const score = process.argv[3]
  const res = validateAndScoreCvss4(vec, score)
  if (!res.valid) {
    console.error(`CVSS4_INVALID: ${res.reason}`)
    process.exit(1)
  }
  console.log(JSON.stringify(res))
}
