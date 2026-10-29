# -*- coding: utf-8 -*-
"""门限恢复的 enrollment 接口（P3.2）。

设计约束（与 spec.md 第 11 节一致）：
  1. 服务器只接收密文，**任何接口都不接受 scores / secret / salt**；
  2. 公钥发布与密文清单都要评委钱包的 EIP-191 签名；
  3. 恢复本身（请求、份额投递、解密）不在本阶段，接口见 P3.3。

路由前缀：/api/recovery
"""
import base64
import binascii
import hashlib
import json
import logging

from flask import Blueprint, jsonify, request
from eth_account import Account
from eth_account.messages import encode_defunct

from utils.auth import auth_required, get_current_user
from models.recovery import Recovery
from models.voting import Voting

logger = logging.getLogger(__name__)
recovery_bp = Blueprint('recovery', __name__)

MANIFEST_SCHEMA = 'ZK-SealedWeigh.recovery.manifest.v1'
SHARE_SCHEMA = 'ZK-SealedWeigh.recovery.share.v1'
KEY_MESSAGE_PREFIX = 'ZK-SealedWeigh.recovery.key.v1'

FORBIDDEN_KEYS = {
    'scores', 'secret', 'salt', 'blinding', 'blinding_factors', 'blindingfactor',
    'masterkey', 'master_key', 'plaintext', 'recovered', 'password',
}

P256_SPKI_BYTES = 91          # P-256 SPKI DER 固定 91 字节
GCM_IV_BYTES = 12


class InvalidPayload(ValueError):
    """请求体不符合协议 → 400"""


SQL_INT_MAX = 2147483647


def _parse_id(value, field):
    """把外部 ID 收敛到 SQL Server INT 范围，避免溢出变成 500。"""
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise InvalidPayload(f'{field} 必须是整数')
    if not (1 <= number <= SQL_INT_MAX):
        raise InvalidPayload(f'{field} 超出范围')
    return number


def _parse_id_arg(name):
    """GET 查询参数里的可选 ID；非法值返回 None，由调用方统一回 400。"""
    raw = request.args.get(name)
    if raw is None or raw == '':
        return None
    try:
        return _parse_id(raw, name)
    except InvalidPayload:
        return None


# ==================== 通用校验 ====================

def _canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _sha256_json(obj):
    return hashlib.sha256(_canonical_json(obj).encode('utf-8')).hexdigest()


def _scan_for_secrets(obj, path=''):
    """递归拒绝任何明文敏感字段。服务器永远不该收到这些东西。"""
    if isinstance(obj, dict):
        for key, value in obj.items():
            normalized = str(key).lower().replace('-', '_')
            if normalized in FORBIDDEN_KEYS:
                raise InvalidPayload(f'禁止字段：{path}{key}')
            _scan_for_secrets(value, f'{path}{key}.')
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            _scan_for_secrets(value, f'{path}[{index}].')


def _b64_bytes(value, field):
    if not isinstance(value, str) or not value:
        raise InvalidPayload(f'{field} 必须是 base64 字符串')
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidPayload(f'{field} 不是合法的 base64')


def _check_p256_spki(value, field):
    raw = _b64_bytes(value, field)
    if len(raw) != P256_SPKI_BYTES or raw[0] != 0x30:
        raise InvalidPayload(f'{field} 不是合法的 P-256 SPKI 公钥')


def _check_cipher_blob(blob, expected_alg, min_ct_bytes, field):
    if not isinstance(blob, dict):
        raise InvalidPayload(f'{field} 必须是对象')
    if blob.get('v') != 1:
        raise InvalidPayload(f'{field}.v 必须为 1')
    if blob.get('alg') != expected_alg:
        raise InvalidPayload(f'{field}.alg 必须为 {expected_alg}')
    iv = _b64_bytes(blob.get('iv'), f'{field}.iv')
    if len(iv) != GCM_IV_BYTES:
        raise InvalidPayload(f'{field}.iv 必须是 {GCM_IV_BYTES} 字节')
    ct = _b64_bytes(blob.get('ct'), f'{field}.ct')
    if len(ct) < min_ct_bytes:
        raise InvalidPayload(f'{field}.ct 长度不足')


def _recover_signer(message, signature, label):
    if not isinstance(signature, str) or not signature.startswith('0x'):
        raise InvalidPayload(f'{label} 缺少 0x 开头的钱包签名')
    try:
        return Account.recover_message(encode_defunct(text=message), signature=signature)
    except Exception:
        raise InvalidPayload(f'{label} 签名无法解析')


def _require_wallet(user):
    wallet = user.get('wallet_address')
    if not wallet or not wallet.startswith('0x') or len(wallet) != 42:
        raise InvalidPayload('当前账号未绑定钱包，无法完成恢复相关操作')
    return wallet


def _load_voting(voting_id):
    voting_id = _parse_id(voting_id, 'votingId')
    voting = Voting.get_voting_by_id(voting_id)
    if not voting:
        raise LookupError('投票活动不存在')
    return voting


def _is_participant(voting, user):
    return user['id'] == voting['creator_id'] or any(
        voter['id'] == user['id'] for voter in voting['voters'])


# ==================== 公钥 ====================

@recovery_bp.route('/keys', methods=['POST'])
@auth_required
def publish_key():
    """发布评委的 ECDH P-256 公钥（SPKI base64），需钱包签名。"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': '用户信息获取失败'}), 401

        data = request.get_json(silent=True) or {}
        _scan_for_secrets(data)

        public_key = data.get('publicKey')
        signature = data.get('signature')
        if not public_key or not signature:
            return jsonify({'success': False, 'message': '需要 publicKey 与 signature'}), 400

        _check_p256_spki(public_key, 'publicKey')
        wallet = _require_wallet(current_user)

        message = f'{KEY_MESSAGE_PREFIX}|{current_user["id"]}|{public_key}'
        signer = _recover_signer(message, signature, '公钥发布')
        if signer.lower() != wallet.lower():
            return jsonify({'success': False, 'message': '签名者与账号绑定钱包不一致'}), 401

        Recovery.upsert_key(current_user['id'], public_key, signature)
        logger.info(f'恢复公钥已登记: user={current_user["id"]} wallet={wallet}')
        return jsonify({
            'success': True,
            'data': {'userId': current_user['id'], 'publicKey': public_key}
        }), 200

    except InvalidPayload as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400
    except Exception as exc:
        logger.error(f'发布恢复公钥失败: {exc}', exc_info=True)
        return jsonify({'success': False, 'message': f'发布公钥失败: {exc}'}), 500


@recovery_bp.route('/keys', methods=['GET'])
@auth_required
def list_keys():
    """读取某活动所有评委的公钥（公开信息，供 enrollment 使用）。"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': '用户信息获取失败'}), 401

        voting_id = _parse_id_arg('votingId')
        if not voting_id:
            return jsonify({'success': False, 'message': '需要 votingId 参数'}), 400

        voting = _load_voting(voting_id)
        if not _is_participant(voting, current_user):
            return jsonify({'success': False, 'message': '无权查看该活动的评委公钥'}), 403
        rows = Recovery.get_keys(voting_id)
        voters = [{
            'userId': row['user_id'],
            'username': row['username'],
            'walletAddress': row['wallet_address'],
            'publicKey': row['public_key'],
        } for row in rows]

        return jsonify({
            'success': True,
            'data': {
                'votingId': voting_id,
                'voters': voters,
                'allKeysReady': all(v['publicKey'] for v in voters),
            }
        }), 200

    except LookupError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 404
    except Exception as exc:
        logger.error(f'读取恢复公钥失败: {exc}', exc_info=True)
        return jsonify({'success': False, 'message': f'读取公钥失败: {exc}'}), 500


# ==================== 密文清单 ====================

@recovery_bp.route('/enroll', methods=['POST'])
@auth_required
def enroll():
    """上传 { 托管密文, 份额信封, 签名清单 }。只接受密文。"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': '用户信息获取失败'}), 401

        data = request.get_json(silent=True) or {}
        _scan_for_secrets(data)

        required = ['votingId', 'escrow', 'envelopes', 'manifest', 'manifestMessage', 'signature']
        missing = [field for field in required if data.get(field) in (None, '', [], {})]
        if missing:
            return jsonify({'success': False, 'message': f'缺少字段：{", ".join(missing)}'}), 400

        voting_id = _parse_id(data['votingId'], 'votingId')
        voting = _load_voting(voting_id)
        if not any(voter['id'] == current_user['id'] for voter in voting['voters']):
            return jsonify({'success': False, 'message': '只有该活动的评委可以登记恢复材料'}), 403
        if voting['phase'] != 'commit':
            return jsonify({'success': False, 'message': '恢复材料只能在承诺阶段登记'}), 409

        # 份额必须逐个加密给全部评委；有人没发布公钥就无法完成覆盖，直接拒绝而不是存半套
        key_rows = Recovery.get_keys(voting_id)
        missing_keys = [row['username'] for row in key_rows if not row['public_key']]
        if missing_keys:
            return jsonify({
                'success': False,
                'message': '以下评委尚未发布恢复公钥：' + ', '.join(missing_keys)
            }), 409

        wallet = _require_wallet(current_user)
        escrow = data['escrow']
        envelopes = data['envelopes']
        manifest = data['manifest']
        manifest_message = data['manifestMessage']

        if not isinstance(envelopes, list) or not envelopes:
            return jsonify({'success': False, 'message': 'envelopes 必须是非空数组'}), 400
        if not isinstance(manifest, dict):
            return jsonify({'success': False, 'message': 'manifest 必须是对象'}), 400

        # ---- 密文结构 ----
        _check_cipher_blob(escrow, 'AES-256-GCM+HKDF-SHA256', 16, 'escrow')
        for index, envelope in enumerate(envelopes):
            _check_cipher_blob(envelope, 'ECDH-P256+HKDF-SHA256+AES-256-GCM', 49,
                               f'envelopes[{index}]')
            _check_p256_spki(envelope.get('epk'), f'envelopes[{index}].epk')

        # ---- 清单与签名绑定 ----
        if manifest.get('schema') != MANIFEST_SCHEMA:
            return jsonify({'success': False, 'message': f'manifest.schema 必须是 {MANIFEST_SCHEMA}'}), 400
        if str(manifest.get('votingId')) != str(voting_id):
            return jsonify({'success': False, 'message': 'manifest.votingId 与请求不一致'}), 400
        if str(manifest.get('voter', '')).lower() != wallet.lower():
            return jsonify({'success': False, 'message': 'manifest.voter 必须是当前评委钱包'}), 400

        expected_message = _canonical_json(manifest)
        if manifest_message != expected_message:
            return jsonify({'success': False, 'message': 'manifestMessage 与 manifest 的规范序列化不一致'}), 400

        if manifest.get('escrowHash') != _sha256_json(escrow):
            return jsonify({'success': False, 'message': 'manifest.escrowHash 与 escrow 密文不匹配'}), 400

        expected_hashes = [_sha256_json(envelope) for envelope in envelopes]
        if manifest.get('envelopeHashes') != expected_hashes:
            return jsonify({'success': False, 'message': 'manifest.envelopeHashes 与信封密文不匹配'}), 400

        # 份额只发给其他评委：自己丢失浏览器时，自己的份额也一并丢失，发给自己没有恢复意义
        expected_recipients = sorted(
            voter['id'] for voter in voting['voters'] if voter['id'] != current_user['id'])
        if not expected_recipients:
            return jsonify({'success': False, 'message': '活动至少需要两位评委才能做门限恢复'}), 409

        recipients = manifest.get('recipients')
        if not isinstance(recipients, list) or sorted(int(x) for x in recipients) != expected_recipients:
            return jsonify({
                'success': False,
                'message': 'recipients 必须覆盖除自己以外的全部评委'
            }), 400
        if len(envelopes) != len(expected_recipients):
            return jsonify({'success': False, 'message': '信封数量必须等于其他评委人数'}), 400

        threshold = manifest.get('threshold')
        if not isinstance(threshold, int) or not (1 <= threshold <= len(expected_recipients)):
            return jsonify({'success': False, 'message': 'threshold 必须满足 1 ≤ k ≤ n（n = 其他评委数）'}), 400

        signer = _recover_signer(manifest_message, data['signature'], '恢复清单')
        if signer.lower() != wallet.lower():
            return jsonify({'success': False, 'message': '清单签名者与评委钱包不一致'}), 401

        Recovery.upsert_enrollment(
            voting_id, current_user['id'], threshold,
            json.dumps(escrow, ensure_ascii=False, sort_keys=True),
            json.dumps(envelopes, ensure_ascii=False, sort_keys=True),
            expected_message,
            data['signature'],
        )

        logger.info(
            f'恢复材料已登记: voting={voting_id} voter={current_user["id"]} '
            f'threshold={threshold}/{len(expected_recipients)}')
        return jsonify({
            'success': True,
            'data': {
                'votingId': voting_id,
                'voterId': current_user['id'],
                'threshold': threshold,
                'recipients': expected_recipients,
                'envelopeCount': len(envelopes),
            }
        }), 201

    except InvalidPayload as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400
    except LookupError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 404
    except (TypeError, ValueError) as exc:
        return jsonify({'success': False, 'message': f'参数格式错误: {exc}'}), 400
    except Exception as exc:
        logger.error(f'登记恢复材料失败: {exc}', exc_info=True)
        return jsonify({'success': False, 'message': f'登记恢复材料失败: {exc}'}), 500


@recovery_bp.route('/enrollments/my', methods=['GET'])
@auth_required
def my_enrollment():
    """评委读取自己的密文清单（用于恢复前的完整性检查）。"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': '用户信息获取失败'}), 401

        voting_id = _parse_id_arg('votingId')
        if not voting_id:
            return jsonify({'success': False, 'message': '需要 votingId 参数'}), 400

        row = Recovery.get_enrollment(voting_id, current_user['id'])
        if not row:
            return jsonify({'success': False, 'message': '尚未登记恢复材料'}), 404

        return jsonify({
            'success': True,
            'data': {
                'votingId': row['voting_id'],
                'voterId': row['voter_id'],
                'threshold': row['threshold'],
                'escrow': json.loads(row['escrow']),
                'envelopes': json.loads(row['envelopes']),
                'manifest': json.loads(row['manifest']),
                'signature': row['manifest_signature'],
                'updatedAt': row['updated_at'].isoformat() if row['updated_at'] else None,
            }
        }), 200

    except Exception as exc:
        logger.error(f'读取恢复材料失败: {exc}', exc_info=True)
        return jsonify({'success': False, 'message': f'读取恢复材料失败: {exc}'}), 500


@recovery_bp.route('/status', methods=['GET'])
@auth_required
def status():
    """活动维度的准备状态：谁发布了公钥、谁已登记（不含任何密文）。"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': '用户信息获取失败'}), 401

        voting_id = _parse_id_arg('votingId')
        if not voting_id:
            return jsonify({'success': False, 'message': '需要 votingId 参数'}), 400

        voting = _load_voting(voting_id)
        if not _is_participant(voting, current_user):
            return jsonify({'success': False, 'message': '无权查看该活动的恢复状态'}), 403

        rows = Recovery.get_status(voting_id)
        voters = [{
            'userId': row['user_id'],
            'username': row['username'],
            'hasKey': bool(row['has_key']),
            'enrolled': bool(row['enrolled']),
            'threshold': row['threshold'],
        } for row in rows]

        return jsonify({
            'success': True,
            'data': {
                'votingId': voting_id,
                'voters': voters,
                'allKeysReady': all(v['hasKey'] for v in voters),
                'allEnrolled': all(v['enrolled'] for v in voters),
            }
        }), 200

    except LookupError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 404
    except Exception as exc:
        logger.error(f'读取恢复状态失败: {exc}', exc_info=True)
        return jsonify({'success': False, 'message': f'读取恢复状态失败: {exc}'}), 500


# ==================== 恢复请求与密文份额（P3.3） ====================

@recovery_bp.route('/request', methods=['POST'])
@auth_required
def create_request():
    """丢失方创建（或复用）恢复请求。请求本身不含任何密文。"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': '用户信息获取失败'}), 401

        data = request.get_json(silent=True) or {}
        _scan_for_secrets(data)
        voting_id = _parse_id(data.get('votingId'), 'votingId')
        if not voting_id:
            return jsonify({'success': False, 'message': '需要 votingId'}), 400

        voting = _load_voting(voting_id)
        if not any(voter['id'] == current_user['id'] for voter in voting['voters']):
            return jsonify({'success': False, 'message': '只有该活动的评委可以发起恢复'}), 403
        if voting['phase'] not in ('commit', 'scoring'):
            return jsonify({'success': False, 'message': '活动已结束，恢复窗口已关闭'}), 409

        enrollment = Recovery.get_enrollment(voting_id, current_user['id'])
        if not enrollment:
            return jsonify({'success': False, 'message': '请先登记恢复材料，再发起恢复'}), 400

        existing = Recovery.get_request_by_voter(voting_id, current_user['id'])
        if existing:
            request_id = int(existing['id'])
            threshold = int(existing['threshold'])
            status = existing['status']
        else:
            request_id = int(Recovery.create_request(
                voting_id, current_user['id'], int(enrollment['threshold'])))
            threshold = int(enrollment['threshold'])
            status = 'open'
            logger.info(f'恢复请求已创建: request={request_id} voting={voting_id} '
                        f'voter={current_user["id"]} threshold={threshold}')

        collected = Recovery.count_shares(request_id)
        return jsonify({
            'success': True,
            'data': {
                'requestId': request_id,
                'votingId': voting_id,
                'threshold': threshold,
                'collected': collected,
                'status': status,
            }
        }), 201 if not existing else 200

    except InvalidPayload as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400
    except LookupError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 404
    except (TypeError, ValueError) as exc:
        return jsonify({'success': False, 'message': f'参数格式错误: {exc}'}), 400
    except Exception as exc:
        logger.error(f'创建恢复请求失败: {exc}', exc_info=True)
        return jsonify({'success': False, 'message': f'创建恢复请求失败: {exc}'}), 500


@recovery_bp.route('/requests', methods=['GET'])
@auth_required
def list_requests():
    """其他评委查看可协助的恢复请求（不含任何密文）。"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': '用户信息获取失败'}), 401

        voting_id = _parse_id_arg('votingId')
        if not voting_id:
            return jsonify({'success': False, 'message': '需要 votingId 参数'}), 400

        voting = _load_voting(voting_id)
        if not _is_participant(voting, current_user):
            return jsonify({'success': False, 'message': '无权查看该活动的恢复请求'}), 403

        rows = Recovery.list_open_requests(voting_id, current_user['id'])
        requests_list = [{
            'requestId': row['id'],
            'votingId': row['voting_id'],
            'requester': {
                'userId': row['voter_id'],
                'username': row['username'],
                'walletAddress': row['wallet_address'],
            },
            'threshold': row['threshold'],
            'collected': row['collected'],
            'submittedByMe': bool(row['submitted_by_me']),
        } for row in rows]

        return jsonify({
            'success': True,
            'data': {'votingId': voting_id, 'requests': requests_list}
        }), 200

    except LookupError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 404
    except Exception as exc:
        logger.error(f'读取恢复请求失败: {exc}', exc_info=True)
        return jsonify({'success': False, 'message': f'读取恢复请求失败: {exc}'}), 500


@recovery_bp.route('/sharebox', methods=['POST'])
@auth_required
def submit_share():
    """其他评委把份额重新加密给请求者后投递。服务器只存密文。"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': '用户信息获取失败'}), 401

        data = request.get_json(silent=True) or {}
        _scan_for_secrets(data)

        required = ['requestId', 'envelope', 'message', 'signature']
        missing = [field for field in required if data.get(field) in (None, '', {}, [])]
        if missing:
            return jsonify({'success': False, 'message': f'缺少字段：{", ".join(missing)}'}), 400

        request_id = _parse_id(data['requestId'], 'requestId')
        recovery_request = Recovery.get_request(request_id)
        if not recovery_request:
            return jsonify({'success': False, 'message': '恢复请求不存在'}), 404
        if recovery_request['status'] != 'open':
            return jsonify({'success': False, 'message': '恢复请求已收集完毕或已关闭'}), 409

        voting_id = int(recovery_request['voting_id'])
        voting = _load_voting(voting_id)
        if not any(voter['id'] == current_user['id'] for voter in voting['voters']):
            return jsonify({'success': False, 'message': '只有该活动的评委可以投递份额'}), 403
        if current_user['id'] == recovery_request['voter_id']:
            return jsonify({'success': False, 'message': '请求者不能给自己投递份额'}), 403

        wallet = _require_wallet(current_user)
        requester_wallet = recovery_request['wallet_address']
        envelope = data['envelope']

        _check_cipher_blob(envelope, 'ECDH-P256+HKDF-SHA256+AES-256-GCM', 49, 'envelope')
        _check_p256_spki(envelope.get('epk'), 'envelope.epk')

        expected_message = _canonical_json({
            'schema': SHARE_SCHEMA,
            'requestId': request_id,
            'votingId': voting_id,
            'from': wallet,
            'to': requester_wallet,
            'envelopeHash': _sha256_json(envelope),
        })
        if data['message'] != expected_message:
            logger.warning(f'份额 message 不一致: expected={expected_message} got={data["message"]}')
            return jsonify({'success': False, 'message': 'message 与份额密文/上下文不一致'}), 400

        signer = _recover_signer(expected_message, data['signature'], '份额投递')
        if signer.lower() != wallet.lower():
            return jsonify({'success': False, 'message': '份额签名者与评委钱包不一致'}), 401

        if Recovery.get_share(request_id, current_user['id']):
            return jsonify({'success': False, 'message': '你已经为本次请求投递过份额'}), 409

        collected = Recovery.add_share(
            request_id, current_user['id'],
            json.dumps(envelope, ensure_ascii=False, sort_keys=True),
            expected_message, data['signature'])

        logger.info(f'恢复份额已投递: request={request_id} from={current_user["id"]} '
                    f'collected={collected}/{recovery_request["threshold"]}')
        return jsonify({
            'success': True,
            'data': {
                'requestId': request_id,
                'collected': collected,
                'threshold': recovery_request['threshold'],
                'ready': collected >= int(recovery_request['threshold']),
            }
        }), 201

    except InvalidPayload as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400
    except LookupError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 404
    except (TypeError, ValueError) as exc:
        return jsonify({'success': False, 'message': f'参数格式错误: {exc}'}), 400
    except Exception as exc:
        logger.error(f'投递恢复份额失败: {exc}', exc_info=True)
        return jsonify({'success': False, 'message': f'投递恢复份额失败: {exc}'}), 500


@recovery_bp.route('/requests/<int:request_id>/envelopes', methods=['GET'])
@auth_required
def request_envelopes(request_id):
    """其他评委读取请求者当初发给自己的份额信封（只有密文，没有 escrow）。"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': '用户信息获取失败'}), 401

        recovery_request = Recovery.get_request(request_id)
        if not recovery_request:
            return jsonify({'success': False, 'message': '恢复请求不存在'}), 404

        voting = _load_voting(int(recovery_request['voting_id']))
        if not any(voter['id'] == current_user['id'] for voter in voting['voters']):
            return jsonify({'success': False, 'message': '只有该活动的评委可以读取份额信封'}), 403

        enrollment = Recovery.get_enrollment(
            int(recovery_request['voting_id']), int(recovery_request['voter_id']))
        if not enrollment:
            return jsonify({'success': False, 'message': '请求者尚未登记恢复材料'}), 404

        manifest = json.loads(enrollment['manifest'])
        return jsonify({
            'success': True,
            'data': {
                'requestId': request_id,
                'votingId': recovery_request['voting_id'],
                'recipientIds': manifest.get('recipients', []),
                'envelopes': json.loads(enrollment['envelopes']),
            }
        }), 200

    except LookupError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 404
    except Exception as exc:
        logger.error(f'读取请求者信封失败: {exc}', exc_info=True)
        return jsonify({'success': False, 'message': f'读取请求者信封失败: {exc}'}), 500


@recovery_bp.route('/sharebox/<int:request_id>', methods=['GET'])
@auth_required
def read_sharebox(request_id):
    """请求者读取已收集的密文份额（其他人无权读取）。"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': '用户信息获取失败'}), 401

        recovery_request = Recovery.get_request(request_id)
        if not recovery_request:
            return jsonify({'success': False, 'message': '恢复请求不存在'}), 404
        if recovery_request['voter_id'] != current_user['id']:
            return jsonify({'success': False, 'message': '只有请求者可以读取份额'}), 403

        rows = Recovery.list_shares(request_id)
        shares = [{
            'fromUserId': row['from_voter_id'],
            'fromUsername': row['username'],
            'fromWallet': row['wallet_address'],
            'envelope': json.loads(row['envelope']),
            'signature': row['signature'],
        } for row in rows]

        return jsonify({
            'success': True,
            'data': {
                'requestId': request_id,
                'votingId': recovery_request['voting_id'],
                'threshold': recovery_request['threshold'],
                'status': recovery_request['status'],
                'shares': shares,
            }
        }), 200

    except Exception as exc:
        logger.error(f'读取份额失败: {exc}', exc_info=True)
        return jsonify({'success': False, 'message': f'读取份额失败: {exc}'}), 500


# ==================== 只读视图：全局待办与恢复历史（P3.10） ====================

def _iso(value):
    return value.isoformat() if value else None


@recovery_bp.route('/overview', methods=['GET'])
@auth_required
def overview():
    """当前用户在进行中活动里的恢复待办（仅元数据，供导航徽标与仪表盘卡片）。"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': '用户信息获取失败'}), 401

        rows, stats, activity_rows = Recovery.get_overview(current_user['id'])
        items = [{
            'requestId': row['id'],
            'votingId': row['voting_id'],
            'votingTitle': row['title'],
            'role': row['role'],
            'requester': {
                'userId': row['voter_id'],
                'username': row['requester_username'],
            },
            'threshold': row['threshold'],
            'collected': int(row['collected'] or 0),
            'status': row['status'],
            'submittedByMe': bool(row['submitted_by_me']),
            'createdAt': _iso(row['created_at']),
        } for row in rows]

        pending_assist = sum(
            1 for item in items
            if item['role'] == 'trustee' and item['status'] == 'open'
            and not item['submittedByMe'])
        my_open = sum(
            1 for item in items
            if item['role'] == 'requester' and item['status'] == 'open')

        return jsonify({
            'success': True,
            'data': {
                'pendingAssist': pending_assist,
                'myOpenRequests': my_open,
                'enrolledCount': int(stats.get('enrolled') or 0),
                'activeVotingCount': int(stats.get('active_votings') or 0),
                'items': items,
                'activities': [{
                    'votingId': row['id'],
                    'title': row['title'],
                    'phase': row['phase'],
                    'enrolled': bool(row['enrolled']),
                    'threshold': row['threshold'],
                    'myOpenRequests': int(row['my_open'] or 0),
                    'pendingAssist': int(row['pending_assist'] or 0),
                } for row in activity_rows],
            }
        }), 200

    except Exception as exc:
        logger.error(f'读取恢复待办失败: {exc}', exc_info=True)
        return jsonify({'success': False, 'message': f'读取恢复待办失败: {exc}'}), 500


@recovery_bp.route('/history', methods=['GET'])
@auth_required
def history():
    """活动内恢复请求与投递记录（只含参与人、时间与状态，不含任何密文）。"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': '用户信息获取失败'}), 401

        voting_id = _parse_id_arg('votingId')
        if not voting_id:
            return jsonify({'success': False, 'message': '需要 votingId 参数'}), 400

        voting = _load_voting(voting_id)
        if not _is_participant(voting, current_user):
            return jsonify({'success': False, 'message': '无权查看该活动的恢复记录'}), 403

        request_rows, share_rows = Recovery.list_history(voting_id)
        shares_by_request = {}
        submitted_request_ids = set()
        for row in share_rows:
            shares_by_request.setdefault(row['request_id'], []).append({
                'fromUserId': row['from_voter_id'],
                'fromUsername': row['username'],
                'fromWallet': row['wallet_address'],
                'createdAt': _iso(row['created_at']),
            })
            if row['from_voter_id'] == current_user['id']:
                submitted_request_ids.add(row['request_id'])

        requests_view = [{
            'requestId': row['id'],
            'requester': {
                'userId': row['voter_id'],
                'username': row['username'],
                'walletAddress': row['wallet_address'],
            },
            'threshold': row['threshold'],
            'collected': int(row['collected'] or 0),
            'status': row['status'],
            'mine': 'requester' if row['voter_id'] == current_user['id'] else 'trustee',
            'submittedByMe': row['id'] in submitted_request_ids,
            'createdAt': _iso(row['created_at']),
            'updatedAt': _iso(row['updated_at']),
            'shares': shares_by_request.get(row['id'], []),
        } for row in request_rows]

        enrollment = Recovery.get_enrollment(voting_id, current_user['id'])
        return jsonify({
            'success': True,
            'data': {
                'votingId': voting_id,
                'myEnrollment': {
                    'enrolled': bool(enrollment),
                    'threshold': enrollment['threshold'] if enrollment else None,
                },
                'requests': requests_view,
            }
        }), 200

    except LookupError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 404
    except Exception as exc:
        logger.error(f'读取恢复记录失败: {exc}', exc_info=True)
        return jsonify({'success': False, 'message': f'读取恢复记录失败: {exc}'}), 500
