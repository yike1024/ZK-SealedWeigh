# -*- coding: utf-8 -*-
"""门限恢复的数据访问层（P3.2）。

只存密文：
  · recovery_keys.public_key     评委的 ECDH P-256 公钥（SPKI base64），公开信息
  · recovery_enrollments.escrow  评委本地载荷的 AES-GCM 密文
  · recovery_enrollments.envelopes  逐个加密给其他评委的 Shamir 份额密文
  · recovery_enrollments.manifest 规范 JSON（含 escrow/信封哈希、threshold）
  · recovery_enrollments.manifest_signature  评委钱包对本条清单的 EIP-191 签名

服务器没有任何字段可以解出明文分数、secret 或 salt。
"""
from database import db


class Recovery:
    # ---------------- 公钥 ----------------

    @staticmethod
    def upsert_key(user_id, public_key, signature):
        db.execute_query(
            """
            IF EXISTS (SELECT 1 FROM recovery_keys WHERE user_id = ?)
                UPDATE recovery_keys
                   SET public_key = ?, signature = ?, updated_at = GETDATE()
                 WHERE user_id = ?
            ELSE
                INSERT INTO recovery_keys (user_id, public_key, signature)
                VALUES (?, ?, ?)
            """,
            (user_id, public_key, signature, user_id, user_id, public_key, signature)
        )

    @staticmethod
    def get_keys(voting_id):
        return db.execute_query(
            """
            SELECT u.id AS user_id, u.username, u.wallet_address, k.public_key
              FROM voting_voters vv
              JOIN users u ON vv.voter_id = u.id
              LEFT JOIN recovery_keys k ON k.user_id = u.id
             WHERE vv.voting_id = ?
             ORDER BY vv.id
            """,
            (voting_id,)
        )

    # ---------------- 密文清单 ----------------

    @staticmethod
    def upsert_enrollment(voting_id, voter_id, threshold,
                          escrow_json, envelopes_json, manifest_json, signature):
        db.execute_query(
            """
            IF EXISTS (SELECT 1 FROM recovery_enrollments WHERE voting_id = ? AND voter_id = ?)
                UPDATE recovery_enrollments
                   SET threshold = ?, escrow = ?, envelopes = ?, manifest = ?,
                       manifest_signature = ?, updated_at = GETDATE()
                 WHERE voting_id = ? AND voter_id = ?
            ELSE
                INSERT INTO recovery_enrollments
                       (voting_id, voter_id, threshold, escrow, envelopes, manifest, manifest_signature)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (voting_id, voter_id,
             threshold, escrow_json, envelopes_json, manifest_json, signature, voting_id, voter_id,
             voting_id, voter_id, threshold, escrow_json, envelopes_json, manifest_json, signature)
        )

    @staticmethod
    def get_enrollment(voting_id, voter_id):
        rows = db.execute_query(
            """
            SELECT voting_id, voter_id, threshold, escrow, envelopes, manifest,
                   manifest_signature, created_at, updated_at
              FROM recovery_enrollments
             WHERE voting_id = ? AND voter_id = ?
            """,
            (voting_id, voter_id)
        )
        return rows[0] if rows else None

    @staticmethod
    def get_status(voting_id):
        return db.execute_query(
            """
            SELECT u.id AS user_id, u.username, u.wallet_address,
                   CASE WHEN k.public_key IS NULL THEN 0 ELSE 1 END AS has_key,
                   CASE WHEN e.id IS NULL THEN 0 ELSE 1 END AS enrolled,
                   e.threshold
              FROM voting_voters vv
              JOIN users u ON vv.voter_id = u.id
              LEFT JOIN recovery_keys k ON k.user_id = u.id
              LEFT JOIN recovery_enrollments e
                     ON e.voting_id = vv.voting_id AND e.voter_id = u.id
             WHERE vv.voting_id = ?
             ORDER BY vv.id
            """,
            (voting_id,)
        )

    # ---------------- 恢复请求 ----------------

    @staticmethod
    def get_request(request_id):
        rows = db.execute_query(
            """
            SELECT r.id, r.voting_id, r.voter_id, r.threshold, r.status,
                   r.created_at, r.updated_at, u.username, u.wallet_address
              FROM recovery_requests r
              JOIN users u ON r.voter_id = u.id
             WHERE r.id = ?
            """,
            (request_id,)
        )
        return rows[0] if rows else None

    @staticmethod
    def get_request_by_voter(voting_id, voter_id):
        rows = db.execute_query(
            """
            SELECT id, voting_id, voter_id, threshold, status, created_at, updated_at
              FROM recovery_requests
             WHERE voting_id = ? AND voter_id = ?
            """,
            (voting_id, voter_id)
        )
        return rows[0] if rows else None

    @staticmethod
    def create_request(voting_id, voter_id, threshold):
        return db.execute_query(
            """
            INSERT INTO recovery_requests (voting_id, voter_id, threshold, status)
            VALUES (?, ?, ?, 'open')
            """,
            (voting_id, voter_id, threshold)
        )

    @staticmethod
    def list_open_requests(voting_id, viewer_id):
        return db.execute_query(
            """
            SELECT r.id, r.voting_id, r.voter_id, r.threshold, r.status, r.created_at,
                   u.username, u.wallet_address,
                   (SELECT COUNT(*) FROM recovery_shares s WHERE s.request_id = r.id) AS collected,
                   CASE WHEN EXISTS (
                        SELECT 1 FROM recovery_shares s2
                         WHERE s2.request_id = r.id AND s2.from_voter_id = ?
                   ) THEN 1 ELSE 0 END AS submitted_by_me
              FROM recovery_requests r
              JOIN users u ON r.voter_id = u.id
             WHERE r.voting_id = ? AND r.status = 'open' AND r.voter_id <> ?
             ORDER BY r.id DESC
            """,
            (viewer_id, voting_id, viewer_id)
        )

    @staticmethod
    def count_shares(request_id):
        rows = db.execute_query(
            'SELECT COUNT(*) AS collected FROM recovery_shares WHERE request_id = ?',
            (request_id,)
        )
        return int(rows[0]['collected']) if rows else 0

    @staticmethod
    def get_share(request_id, from_voter_id):
        rows = db.execute_query(
            'SELECT id FROM recovery_shares WHERE request_id = ? AND from_voter_id = ?',
            (request_id, from_voter_id)
        )
        return rows[0] if rows else None

    @staticmethod
    def add_share(request_id, from_voter_id, envelope_json, message, signature):
        db.execute_query(
            """
            INSERT INTO recovery_shares (request_id, from_voter_id, envelope, message, signature)
            VALUES (?, ?, ?, ?, ?)
            """,
            (request_id, from_voter_id, envelope_json, message, signature)
        )
        collected = Recovery.count_shares(request_id)
        request = Recovery.get_request(request_id)
        if request and collected >= int(request['threshold']) and request['status'] == 'open':
            db.execute_query(
                "UPDATE recovery_requests SET status = 'collected', updated_at = GETDATE() WHERE id = ?",
                (request_id,)
            )
        return collected

    @staticmethod
    def list_shares(request_id):
        return db.execute_query(
            """
            SELECT s.id, s.from_voter_id, s.envelope, s.message, s.signature, s.created_at,
                   u.username, u.wallet_address
              FROM recovery_shares s
              JOIN users u ON s.from_voter_id = u.id
             WHERE s.request_id = ?
             ORDER BY s.id
            """,
            (request_id,)
        )

    # ---------------- 只读视图（P3.10） ----------------

    @staticmethod
    def get_overview(user_id):
        """当前用户在进行中活动里的恢复待办（仅元数据）。"""
        rows = db.execute_query(
            """
            SELECT r.id, r.voting_id, vs.title, r.voter_id, r.threshold, r.status,
                   r.created_at, u.username AS requester_username,
                   (SELECT COUNT(*) FROM recovery_shares s
                     WHERE s.request_id = r.id) AS collected,
                   CASE WHEN EXISTS (
                        SELECT 1 FROM recovery_shares s2
                         WHERE s2.request_id = r.id AND s2.from_voter_id = ?
                   ) THEN 1 ELSE 0 END AS submitted_by_me,
                   CASE WHEN r.voter_id = ? THEN 'requester' ELSE 'trustee' END AS role
              FROM recovery_requests r
              JOIN voting_sessions vs ON vs.id = r.voting_id
              JOIN users u ON u.id = r.voter_id
              JOIN voting_voters vv ON vv.voting_id = r.voting_id AND vv.voter_id = ?
             WHERE vs.phase IN ('commit', 'scoring')
               AND (r.voter_id = ? OR NOT EXISTS (
                     SELECT 1 FROM recovery_shares s3
                      WHERE s3.request_id = r.id AND s3.from_voter_id = ?
               ))
             ORDER BY r.created_at DESC, r.id DESC
            """,
            (user_id, user_id, user_id, user_id, user_id)
        )

        stats = db.execute_query(
            """
            SELECT COUNT(*) AS active_votings,
                   SUM(CASE WHEN e.id IS NULL THEN 0 ELSE 1 END) AS enrolled
              FROM voting_voters vv
              JOIN voting_sessions vs ON vs.id = vv.voting_id
              LEFT JOIN recovery_enrollments e
                     ON e.voting_id = vv.voting_id AND e.voter_id = vv.voter_id
             WHERE vv.voter_id = ? AND vs.phase IN ('commit', 'scoring')
            """,
            (user_id,)
        )

        activities = db.execute_query(
            """
            SELECT vs.id, vs.title, vs.phase,
                   CASE WHEN e.id IS NULL THEN 0 ELSE 1 END AS enrolled,
                   e.threshold,
                   (SELECT COUNT(*) FROM recovery_requests r
                     WHERE r.voting_id = vs.id AND r.voter_id = ?
                       AND r.status = 'open') AS my_open,
                   (SELECT COUNT(*) FROM recovery_requests r2
                     WHERE r2.voting_id = vs.id AND r2.voter_id <> ?
                       AND r2.status = 'open'
                       AND NOT EXISTS (
                           SELECT 1 FROM recovery_shares s
                            WHERE s.request_id = r2.id AND s.from_voter_id = ?
                       )) AS pending_assist
              FROM voting_voters vv
              JOIN voting_sessions vs ON vs.id = vv.voting_id
              LEFT JOIN recovery_enrollments e
                     ON e.voting_id = vs.id AND e.voter_id = vv.voter_id
             WHERE vv.voter_id = ? AND vs.phase IN ('commit', 'scoring')
             ORDER BY vs.created_at DESC, vs.id DESC
            """,
            (user_id, user_id, user_id, user_id)
        )

        return rows, (stats[0] if stats else {'active_votings': 0, 'enrolled': 0}), activities

    @staticmethod
    def list_history(voting_id):
        """活动内全部恢复请求与投递记录（只含元数据，无密文）。"""
        requests = db.execute_query(
            """
            SELECT r.id, r.voting_id, r.voter_id, r.threshold, r.status,
                   r.created_at, r.updated_at,
                   u.username, u.wallet_address,
                   (SELECT COUNT(*) FROM recovery_shares s
                     WHERE s.request_id = r.id) AS collected
              FROM recovery_requests r
              JOIN users u ON u.id = r.voter_id
             WHERE r.voting_id = ?
             ORDER BY r.created_at DESC, r.id DESC
            """,
            (voting_id,)
        )
        shares = db.execute_query(
            """
            SELECT s.request_id, s.from_voter_id, s.created_at,
                   u.username, u.wallet_address
              FROM recovery_shares s
              JOIN users u ON u.id = s.from_voter_id
             WHERE s.request_id IN (
                   SELECT id FROM recovery_requests WHERE voting_id = ?
             )
             ORDER BY s.id
            """,
            (voting_id,)
        )
        return requests, shares

    @staticmethod
    def delete_request_data(voting_id):
        """测试/运维用：按活动清理恢复请求与份额（先份额后请求）。"""
        db.execute_query(
            """
            DELETE FROM recovery_shares
             WHERE request_id IN (SELECT id FROM recovery_requests WHERE voting_id = ?)
            """,
            (voting_id,)
        )
        db.execute_query('DELETE FROM recovery_requests WHERE voting_id = ?', (voting_id,))
