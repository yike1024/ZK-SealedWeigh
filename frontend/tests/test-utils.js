/**
 * 测试侧共用的小工具：直接转发浏览器/Node 共用的规范 JSON 与 sha256，
 * 避免测试与生产出现第二套实现。
 */
const { canonicalJson, sha256Hex } = require('../recovery-manifest.js');

module.exports = { canonicalJson, sha256Hex };
