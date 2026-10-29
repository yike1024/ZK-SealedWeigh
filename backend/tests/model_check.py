# -*- coding: utf-8 -*-
"""P4 有界模型检验（bounded model checking）。

对评审协议的状态机做显式状态枚举：
  · phase：1 承诺 / 2 评分 / 3 完成
  · committed / revealed：每位评委
  · nullifier：活动内不可复用
  · results：按 view 权重累加（模型统一权重 1）

两类模型：
  1. 设计模型（阶段单调前进）：穷举深度内所有轨迹，检查 8 条安全不变量；
  2. 缺陷模型（还原 P4 修复前的合约规则，允许阶段回退）：
     检验方法本身能否在浅层找到反例。

注意：这是**有界**模型检验，不是无限状态的数学证明；它覆盖的是
显式建模的状态与深度内所有交错。运行：
    cd backend
    $env:PYTHONUTF8='1'; python tests\\model_check.py
退出码：0 = 设计模型无违规且缺陷模型能找到反例。
"""
import sys
from collections import deque

VOTERS = 2
CANDIDATES = 2
MAX_SCORE = 1          # 分数域 {0,1}，控制状态空间
MAX_DEPTH = 6
STATE_LIMIT = 200000

SCORE_VECTORS = [
    (a, b) for a in range(MAX_SCORE + 1) for b in range(MAX_SCORE + 1)
]
NULLIFIERS = (0, 1)

passed = 0
failed = 0


def check(name, condition, detail=''):
    global passed, failed
    if condition:
        passed += 1
        print(f'  [PASS] {name}')
    else:
        failed += 1
        print(f'  [FAIL] {name} {detail}')


def initial_state():
    return {
        'phase': 1,
        'active': True,
        'committed': (False,) * VOTERS,
        'revealed': (False,) * VOTERS,
        'scores': (None,) * VOTERS,
        'nullifiers': frozenset(),
        'results': (0,) * CANDIDATES,
        'time_elapsed': False,
        'settled': False,
        'max_phase': 1,
    }


def state_key(state):
    return (
        state['phase'], state['active'], state['committed'], state['revealed'],
        state['scores'], state['nullifiers'], state['results'],
        state['time_elapsed'], state['settled'], state['max_phase'],
    )


def actions(state, monotonic):
    phase = state['phase']
    if not state['active']:
        return []

    result = []
    for target in range(1, 4):
        if target == phase:
            continue
        if monotonic and target < phase:
            continue
        result.append(('update_phase', target))

    if phase == 1:
        for voter in range(VOTERS):
            if not state['committed'][voter]:
                result.append(('commit', voter))

    if phase == 2:
        for voter in range(VOTERS):
            if state['committed'][voter] and not state['revealed'][voter]:
                for scores in SCORE_VECTORS:
                    for nullifier in NULLIFIERS:
                        if nullifier not in state['nullifiers']:
                            result.append(('reveal', voter, scores, nullifier))
        if state['time_elapsed'] and not state['settled']:
            result.append(('settle',))

    if not state['time_elapsed']:
        result.append(('tick',))
    result.append(('end',))
    return result


def apply(state, action, monotonic):
    new = dict(state)
    kind = action[0]

    if kind == 'tick':
        new['time_elapsed'] = True
    elif kind == 'end':
        new['active'] = False
        new['phase'] = 3
        new['max_phase'] = 3
    elif kind == 'update_phase':
        target = action[1]
        if not monotonic and target < state['phase'] and state['max_phase'] > target:
            new['phase'] = target
            # 不更新 max_phase，留给不变量检测"曾到达更高阶段后回退"
        else:
            new['phase'] = target
            new['max_phase'] = max(state['max_phase'], target)
    elif kind == 'commit':
        voter = action[1]
        committed = list(new['committed'])
        committed[voter] = True
        new['committed'] = tuple(committed)
    elif kind == 'reveal':
        _, voter, scores, nullifier = action
        revealed = list(new['revealed'])
        revealed[voter] = True
        new['revealed'] = tuple(revealed)
        stored = list(new['scores'])
        stored[voter] = scores
        new['scores'] = tuple(stored)
        new['nullifiers'] = state['nullifiers'] | {nullifier}
        results = list(new['results'])
        for index, value in enumerate(scores):
            results[index] += value
        new['results'] = tuple(results)
    elif kind == 'settle':
        new['phase'] = 3
        new['settled'] = True
        new['max_phase'] = 3

    return new


def invariant_violation(state, monotonic):
    """返回违反的不变量名称，全部通过返回 None。"""
    for voter in range(VOTERS):
        if state['revealed'][voter] and not state['committed'][voter]:
            return 'reveal_without_commit'
        scores = state['scores'][voter]
        if scores is not None:
            if len(scores) != CANDIDATES:
                return 'wrong_score_length'
            if any(value < 0 or value > MAX_SCORE for value in scores):
                return 'score_out_of_range'

    expected = [0] * CANDIDATES
    for voter in range(VOTERS):
        scores = state['scores'][voter]
        if scores:
            for index, value in enumerate(scores):
                expected[index] += value
    if tuple(expected) != state['results']:
        return 'results_mismatch'

    if state['settled'] and state['phase'] != 3:
        return 'settled_not_completed'
    if not state['active'] and state['phase'] != 3:
        return 'inactive_not_completed'
    if state['phase'] == 1 and any(state['revealed']):
        return 'reveal_in_commit_phase'
    if not monotonic and state['phase'] < state['max_phase']:
        return 'phase_regression'
    return None


def explore(monotonic, max_depth):
    """BFS 枚举深度内所有可达状态；返回统计、违规与反例轨迹。"""
    start = initial_state()
    queue = deque([(start, [])])
    seen = set()
    transitions = 0
    first_violation = None
    deepest = 0

    while queue and len(seen) < STATE_LIMIT:
        state, trace = queue.popleft()
        key = state_key(state)
        if key in seen:
            continue
        seen.add(key)
        deepest = max(deepest, len(trace))

        violation = invariant_violation(state, monotonic)
        if violation and first_violation is None:
            first_violation = (violation, trace, state)

        if len(trace) >= max_depth:
            continue

        for action in actions(state, monotonic):
            transitions += 1
            new_state = apply(state, action, monotonic)
            if state_key(new_state) == key:
                continue
            queue.append((new_state, trace + [action]))

    return {
        'states': len(seen),
        'transitions': transitions,
        'deepest': deepest,
        'violation': first_violation,
        'truncated': bool(queue),
    }


def format_trace(trace):
    parts = []
    for action in trace:
        if action[0] == 'update_phase':
            parts.append(f'update_phase({action[1]})')
        elif action[0] == 'reveal':
            parts.append(f'reveal(v{action[1]}, {action[2]}, nf{action[3]})')
        elif action[0] == 'commit':
            parts.append(f'commit(v{action[1]})')
        else:
            parts.append(action[0])
    return ' -> '.join(parts) if parts else '(initial)'


def main():
    print('\n=== P4 有界模型检验（阶段 1-3 / 2 评委 / 2 候选 / 分数域 0-1）===\n')

    print('--- 1. 设计模型（阶段单调）---')
    design = explore(monotonic=True, max_depth=MAX_DEPTH)
    check('设计模型无安全不变量违规', design['violation'] is None,
          design['violation'])
    check('显式状态枚举达到有效规模',
          design['states'] >= 100 and not design['truncated'],
          design)
    check('覆盖到最大深度', design['deepest'] == MAX_DEPTH,
          design['deepest'])
    print(f"  状态 {design['states']} / 迁移 {design['transitions']} / 深度 {design['deepest']}")

    print('\n--- 2. 缺陷模型（允许阶段回退）---')
    buggy = explore(monotonic=False, max_depth=3)
    violation = buggy['violation']
    check('缺陷模型能找到阶段回退反例',
          violation is not None and violation[0] == 'phase_regression',
          violation)
    if violation:
        print(f"  不变量: {violation[0]}")
        print(f"  反例轨迹: {format_trace(violation[1])}")
        check('反例轨迹包含阶段回退动作',
              any(action[0] == 'update_phase' for action in violation[1]),
              format_trace(violation[1]))
        check('反例在浅层（<=3 步）出现', len(violation[1]) <= 3,
              len(violation[1]))
        check('反例证明“完成/评分后仍可回到承诺阶段”',
              max(action[1] for action in violation[1]
                  if action[0] == 'update_phase') >= 2,
              format_trace(violation[1]))

    print(f"\n=== 结果：{passed} 通过 / {failed} 失败 ===")
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
