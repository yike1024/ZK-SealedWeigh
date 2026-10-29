# -*- coding: utf-8 -*-
"""P4 接口模糊测试（确定性语料 + 种子随机）。

目标：恶意/畸形输入只能得到 4xx，**绝不能 500**，也不能把数据库/SQL 细节
或任何明文材料回显出来。不构造合法写操作，避免污染业务数据。

运行：
    cd backend
    $env:PYTHONUTF8='1'; python tests\\test_fuzz_api.py
退出码：0 = 全部通过。
"""
import json
import random
import sys

import requests

API = 'http://127.0.0.1:5000/api'
SEED = 0x5EED2026


def login(username, password='123456'):
    response = requests.post(f'{API}/auth/login',
                             json={'username': username, 'password': password},
                             timeout=15)
    response.raise_for_status()
    return response.json()['data']['token']


def auth(token):
    return {'Authorization': f'Bearer {token}'}


BAD_MARKERS = (
    'Traceback (most recent call last)',
    'OperationalError',
    'pyodbc',
    'pymssql',
    'SECRET_SCALAR',
    'correct horse battery staple',
)


def weird_values():
    return [
        None, True, False, 0, -1, 10 ** 40, '', 'x' * 8192,
        '中文🙂\x00', [], [1, 2, 3], {}, {'nested': {'deep': [None]}},
        'undefined', 'NaN', '../etc/passwd', "'; DROP TABLE users;--",
    ]


def random_value(rng):
    kind = rng.randrange(6)
    if kind == 0:
        return rng.choice(weird_values())
    if kind == 1:
        return rng.randint(-10 ** 6, 10 ** 6)
    if kind == 2:
        return ''.join(chr(rng.randrange(32, 0x2FFF)) for _ in range(rng.randrange(0, 64)))
    if kind == 3:
        return [random_value(rng) for _ in range(rng.randrange(0, 4))]
    if kind == 4:
        return {f'k{i}': random_value(rng) for i in range(rng.randrange(0, 4))}
    return rng.random()


def cases():
    """返回 (name, method, path, headers, body, content_type, allowed_status)。"""
    voter = login('voter1')
    admin = login('admin')
    v = auth(voter)
    a = auth(admin)

    yield ('登录-空体', 'POST', '/auth/login', {}, None, 'application/json', {400, 401, 422})
    yield ('登录-数组', 'POST', '/auth/login', {}, [1, 2], 'application/json', {400, 401, 422})
    yield ('登录-超长字符串', 'POST', '/auth/login', {},
           {'username': 'x' * 8192, 'password': 'y' * 8192}, 'application/json',
           {400, 401, 422})
    yield ('登录-错误类型', 'POST', '/auth/login', {},
           {'username': {'a': 1}, 'password': [1]}, 'application/json',
           {400, 401, 422})
    yield ('登录-畸形JSON', 'POST', '/auth/login', {},
           '{"username": "voter1", ', 'application/json', {400, 401, 422})
    yield ('登录-错误ContentType', 'POST', '/auth/login', {},
           'username=voter1&password=123456', 'text/plain', {400, 401, 415, 422})

    yield ('公钥-空体', 'POST', '/recovery/keys', v, {}, 'application/json',
           {400, 401, 422})
    yield ('公钥-类型错误', 'POST', '/recovery/keys', v,
           {'publicKey': 123, 'signature': []}, 'application/json', {400, 401, 422})
    yield ('公钥-超长', 'POST', '/recovery/keys', v,
           {'publicKey': 'A' * 8192, 'signature': '0x' + '0' * 130}, 'application/json',
           {400, 401, 422})

    yield ('登记-空体', 'POST', '/recovery/enroll', v, {}, 'application/json',
           {400, 401, 422})
    yield ('登记-投票ID字符串', 'POST', '/recovery/enroll', v,
           {'votingId': 'abc'}, 'application/json', {400, 401, 422})
    yield ('登记-清单为数组', 'POST', '/recovery/enroll', v,
           {'votingId': 1, 'manifest': [1, 2, 3]}, 'application/json',
           {400, 401, 422})
    yield ('登记-明文注入', 'POST', '/recovery/enroll', v,
           {'votingId': 1, 'scores': [7, 9, 0], 'secret': 'x'}, 'application/json',
           {400, 401, 422})

    yield ('请求-负数ID', 'POST', '/recovery/request', v,
           {'votingId': -1}, 'application/json', {400, 403, 404, 422})
    yield ('请求-超大ID', 'POST', '/recovery/request', v,
           {'votingId': 10 ** 30}, 'application/json', {400, 403, 404, 422})
    yield ('请求-对象ID', 'POST', '/recovery/request', v,
           {'votingId': {'x': 1}}, 'application/json', {400, 403, 404, 422})

    yield ('份额-不存在请求', 'POST', '/recovery/sharebox', v,
           {'requestId': 999999, 'envelope': {}, 'message': 'x', 'signature': '0x'},
           'application/json', {400, 401, 403, 404, 422})
    yield ('份额-数组信封', 'POST', '/recovery/sharebox', v,
           {'requestId': [1], 'envelope': [1, 2], 'message': [], 'signature': {}},
           'application/json', {400, 401, 403, 404, 422})

    yield ('历史-非法ID', 'GET', '/recovery/history?votingId=abc', v, None,
           None, {400, 403, 404, 422})
    yield ('历史-负数ID', 'GET', '/recovery/history?votingId=-1', v, None,
           None, {400, 403, 404, 422})
    yield ('历史-不存在活动', 'GET', '/recovery/history?votingId=999999', v, None,
           None, {404})
    yield ('总览-畸形参数', 'GET', '/recovery/overview?x=%00', v, None, None, {200})

    yield ('建活动-空体', 'POST', '/voting/', a, {}, 'application/json',
           {400, 401, 403, 422})
    yield ('建活动-字段类型错误', 'POST', '/voting/', a,
           {'title': {'a': 1}, 'candidates': 'x', 'voters': 3},
           'application/json', {400, 401, 403, 422})
    yield ('建活动-候选不足', 'POST', '/voting/', a,
           {'title': 'x', 'candidates': ['A'], 'voters': ['voter1']},
           'application/json', {400, 401, 403, 422})
    yield ('建活动-畸形JSON', 'POST', '/voting/', a, '[', 'application/json',
           {400, 401, 403, 422})

    yield ('阶段-非法活动', 'PUT', '/voting/999999/phase', a,
           {'phase': 'commit'}, 'application/json', {400, 403, 404, 422})
    yield ('阶段-非法值', 'PUT', '/voting/999999/phase', a,
           {'phase': ['commit']}, 'application/json', {400, 403, 404, 422})

    yield ('后门-恢复接口', 'POST', '/scores/recover', a,
           {'votingId': 1}, 'application/json', {410})
    yield ('后门-空体', 'POST', '/scores/recover', a, None, None, {410})

    # ---------- 认证头与权限 ----------
    malformed_headers = [
        {},
        {'Authorization': ''},
        {'Authorization': 'Bearer'},
        {'Authorization': 'Bearer ' + 'x' * 4096},
        {'Authorization': 'Bearer abc.def.ghi'},
        {'Authorization': 'Basic ' + 'A' * 32},
    ]
    for index, headers in enumerate(malformed_headers):
        yield (f'认证-畸形头-{index}', 'GET', '/auth/me', headers, None, None,
               {400, 401, 403, 422})

    yield ('认证-方法不允许', 'POST', '/auth/me', a, {}, 'application/json', {405})
    yield ('认证-钱包校验-数组体', 'POST', '/auth/wallet/validate', v, [1],
           'application/json', {400, 401, 422})
    yield ('认证-钱包校验-对象地址', 'POST', '/auth/wallet/validate', v,
           {'wallet_address': {'x': 1}}, 'application/json', {400, 401, 422})
    yield ('认证-批量用户-数组体', 'POST', '/auth/users/batch', v, [1],
           'application/json', {400, 401, 422})
    yield ('认证-批量用户-非字符串', 'POST', '/auth/users/batch', v,
           {'usernames': [123, None, True]}, 'application/json', {400, 401, 422})
    yield ('认证-批量用户-超长字符串', 'POST', '/auth/users/batch', v,
           {'usernames': ['x' * 8192]}, 'application/json', {400, 401, 422})
    yield ('认证-用户查询-超长', 'GET', '/auth/user/' + 'x' * 300, v, None,
           None, {400, 404, 422})
    yield ('认证-钱包状态-无token', 'GET', '/auth/wallet/status', {}, None,
           None, {401})

    # ---------- 旧评分接口（应只读拒绝） ----------
    yield ('评分-旧接口-数组体', 'POST', '/scores/', v, [1, 2],
           'application/json', {400, 401, 403, 410, 422})
    yield ('评分-旧接口-空体', 'POST', '/scores/', v, {}, 'application/json',
           {400, 401, 403, 410, 422})
    yield ('评分-旧接口-类型混淆', 'POST', '/scores/', v,
           {'voting_id': {'x': 1}, 'candidate_id': [], 'score': 'x'},
           'application/json', {400, 401, 403, 410, 422})
    yield ('评分-批量-数组体', 'POST', '/scores/batch', v, [1],
           'application/json', {400, 401, 403, 410, 422})
    yield ('评分-批量-字段类型', 'POST', '/scores/batch', v,
           {'voting_id': {}, 'scores': 'x'}, 'application/json',
           {400, 401, 403, 410, 422})

    # ---------- 权重接口 ----------
    weight_statuses = {400, 401, 403, 404, 409, 422}
    yield ('权重-数组体', 'PUT', '/weights/voting/999999/voter/1', a, [1, 2],
           'application/json', weight_statuses)
    yield ('权重-对象权重', 'PUT', '/weights/voting/999999/voter/1', a,
           {'weight': {'x': 1}}, 'application/json', weight_statuses)
    yield ('权重-字符串权重', 'PUT', '/weights/voting/999999/voter/1', a,
           {'weight': 'abc'}, 'application/json', weight_statuses)
    yield ('权重-批量-数组体', 'PUT', '/weights/voting/999999/batch-weights', a,
           [1], 'application/json', weight_statuses)
    yield ('权重-批量-元素非字典', 'PUT', '/weights/voting/999999/batch-weights',
           a, {'updates': [1, 2]}, 'application/json', weight_statuses)
    yield ('权重-批量-权重类型', 'PUT', '/weights/voting/999999/batch-weights',
           a, {'updates': [{'voter_id': 1, 'weight': {'x': 1}}]},
           'application/json', weight_statuses)
    yield ('权重-查询-超大ID', 'GET', '/weights/voting/999999999999999999999/weights',
           a, None, None, {400, 403, 404, 422})

    # ---------- 承诺 / 阶段 / 结果 ----------
    yield ('承诺-数组体', 'POST', '/voting/1/commitments', v, [1],
           'application/json', {400, 401, 403, 422})
    yield ('承诺-空体', 'POST', '/voting/1/commitments', v, {},
           'application/json', {400, 401, 403, 422})
    yield ('承诺-明文注入', 'POST', '/voting/1/commitments', v,
           {'commitments': [], 'commitment_hash': '0x' + '0' * 64, 'scores': [1]},
           'application/json', {400, 401, 403, 422})
    yield ('范围证明-缺签名', 'POST', '/voting/1/onchain/relay', v,
           {'action': 'range'}, 'application/json', {400, 401, 403, 422})
    yield ('链上代发-数组体', 'POST', '/voting/1/onchain/relay', v, [1],
           'application/json', {400, 401, 403, 422})
    yield ('链上代发-非法动作', 'POST', '/voting/1/onchain/relay', v,
           {'action': {'x': 1}, 'signature': '0x'}, 'application/json',
           {400, 401, 403, 422})
    yield ('阶段-数组体', 'PUT', '/voting/1/phase', a, [1],
           'application/json', {400, 401, 403, 422})
    yield ('阶段-对象值', 'PUT', '/voting/1/phase', a, {'phase': {'x': 1}},
           'application/json', {400, 401, 403, 422})
    yield ('结果-超大ID', 'GET', '/voting/999999999999999999999/results', v,
           None, None, {400, 403, 404, 422})
    yield ('结果-负数ID', 'GET', '/voting/-1/results', v, None, None,
           {400, 404, 422})
    yield ('我的承诺-超大ID', 'GET',
           '/voting/999999999999999999999/commitments/my', v, None, None,
           {400, 403, 404, 422})

    # ---------- 区块链只读 / 调试接口 ----------
    yield ('链状态-超大ID', 'GET',
           '/blockchain/voting/999999999999999999999/status', v, None, None,
           {400, 403, 404, 422})
    yield ('链信息-非法ID', 'GET', '/blockchain/voting/abc/info', v, None,
           None, {404})
    yield ('链提交承诺-数组体', 'POST', '/blockchain/submit-commitment', a, [1],
           'application/json', {400, 401, 403, 422})
    yield ('链揭晓-数组体', 'POST', '/blockchain/reveal-scores', a, [1],
           'application/json', {400, 401, 403, 422})

    rng = random.Random(SEED)
    endpoints = [
        ('POST', '/recovery/keys', v),
        ('POST', '/recovery/enroll', v),
        ('POST', '/recovery/request', v),
        ('POST', '/recovery/sharebox', v),
        ('POST', '/voting/', a),
    ]
    for index in range(40):
        method, path, headers = endpoints[index % len(endpoints)]
        body = {f'f{index}_{rng.randrange(5)}': random_value(rng)
                for _ in range(rng.randrange(0, 5))}
        yield (f'随机-{index}', method, path, headers, body, 'application/json',
               {400, 401, 403, 404, 409, 410, 413, 415, 422})


def main():
    total = 0
    failures = []
    status_counts = {}

    for name, method, path, headers, body, content_type, allowed in cases():
        total += 1
        kwargs = {'headers': headers, 'timeout': 30}
        if body is not None:
            if isinstance(body, str):
                kwargs['data'] = body.encode('utf-8')
            else:
                kwargs['json'] = body
            if content_type:
                kwargs['headers'] = dict(headers, **{'Content-Type': content_type})

        try:
            response = requests.request(method, API + path, **kwargs)
        except Exception as exc:                       # 连接层错误也要记录
            failures.append((name, 'EXC', str(exc)[:160]))
            continue

        status_counts[response.status_code] = status_counts.get(response.status_code, 0) + 1
        text = response.text or ''

        if response.status_code >= 500:
            failures.append((name, response.status_code, text[:200]))
            continue
        if response.status_code not in allowed:
            failures.append((name, response.status_code,
                             f'expected {sorted(allowed)} :: {text[:160]}'))
            continue
        for marker in BAD_MARKERS:
            if marker in text:
                failures.append((name, response.status_code, f'leaked marker: {marker}'))
                break

    print(f'\n=== P4 接口模糊测试：{total} 个用例 ===')
    print('状态码分布:', dict(sorted(status_counts.items())))

    if failures:
        print(f'\n[FAIL] {len(failures)} 个用例不符合预期：')
        for item in failures[:20]:
            print('  -', item)
        print('\n=== 结果：失败 ===')
        return 1

    print('  [PASS] 所有用例均为 4xx/预期状态，未出现 500')
    print('  [PASS] 响应中未出现堆栈、数据库驱动名或明文材料')
    print(f'\n=== 结果：{total} 通过 / 0 失败 ===')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
