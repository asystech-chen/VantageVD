/**
 * 评分判定模型回归测试：**主干定生死 + 环境分封顶**（2026-10-12）。
 *
 * 断言：
 *   - 未命中主干（规则一 strong）时，环境分无论多高都被封顶 → 恒不告警（消除正常站误报）
 *   - 命中主干 → 直接判高危
 *   - weak（规则一低置信）只计入环境分，不单独触发
 *   - 站点黑名单（siteBlacklist）等附加规则也计入环境分
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { ScoringEngine } from '../background/scoring-engine.js';
import { ENV_SCORE_CAP, SCORE_THRESHOLD } from '../utils/constants.js';

const noTrunk = { score: 0, triggered: false, status: 'pass' };

test('无主干：环境分再高也被封顶，不告警', () => {
  const bd = {
    rule1: noTrunk,
    rule2: { score: 40, triggered: true },
    rule3: { score: 50, triggered: true },
    rule4: { score: 70, triggered: true },
    rule5: { score: 30, triggered: true },
    domainAge: { score: 60, triggered: true },
    ageBonus: { score: 0 }
  };
  const v = ScoringEngine.computeVerdict(bd);
  assert.equal(v.strongTrunk, false);
  assert.equal(v.totalScore, ENV_SCORE_CAP, '环境分封顶为 ENV_SCORE_CAP');
  assert.ok(v.totalScore < SCORE_THRESHOLD, '封顶后必须低于告警阈值');
  assert.equal(v.isSuspicious, false);
});

test('主干 strong：直接判高危', () => {
  const bd = {
    rule1: { score: 60, triggered: true, severity: 'strong' },
    rule2: { score: 0 }, rule3: { score: 0 }, rule4: { score: 0 }, rule5: { score: 0 },
    domainAge: { score: 0 }, ageBonus: { score: 0 }
  };
  const v = ScoringEngine.computeVerdict(bd);
  assert.equal(v.strongTrunk, true);
  assert.ok(v.totalScore >= SCORE_THRESHOLD);
  assert.equal(v.isSuspicious, true);
});

test('主干 strong + 环境分：总分高于阈值且不超 主干+封顶', () => {
  const bd = {
    rule1: { score: 60, triggered: true, severity: 'strong' },
    rule2: { score: 20 }, rule3: { score: 50 }, rule4: { score: 20 }, rule5: { score: 20 },
    domainAge: { score: 60 }, ageBonus: { score: 0 }
  };
  const v = ScoringEngine.computeVerdict(bd);
  assert.equal(v.isSuspicious, true);
  assert.equal(v.totalScore, 60 + ENV_SCORE_CAP, '环境分被封顶在 ENV_SCORE_CAP');
});

test('weak（低置信）只计入环境分，不单独触发', () => {
  const bd = {
    rule1: { score: 20, triggered: true, severity: 'weak' },
    rule2: { score: 0 }, rule3: { score: 0 }, rule4: { score: 0 }, rule5: { score: 0 },
    domainAge: { score: 0 }, ageBonus: { score: 0 }
  };
  const v = ScoringEngine.computeVerdict(bd);
  assert.equal(v.strongTrunk, false);
  assert.equal(v.totalScore, 20, 'weak 20 计入环境分');
  assert.equal(v.isSuspicious, false);
});

test('站点黑名单等附加规则计入环境分', () => {
  const bd = {
    rule1: noTrunk,
    siteBlacklist: { score: 60, triggered: true }
  };
  const v = ScoringEngine.computeVerdict(bd);
  assert.equal(v.totalScore, ENV_SCORE_CAP);
  assert.equal(v.isSuspicious, false, '单靠环境分不触发（黑名单有独立强制流程）');
});

test('域名年龄减分（负分）不会使总分低于 0', () => {
  const bd = {
    rule1: noTrunk,
    rule3: { score: 10 },
    domainAge: { score: 0 },
    ageBonus: { score: -20 }
  };
  const v = ScoringEngine.computeVerdict(bd);
  assert.ok(v.totalScore >= 0);
});
