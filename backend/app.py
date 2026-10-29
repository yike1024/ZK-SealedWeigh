# backend/app.py - 完整修复版本（解决投票蓝图注册问题）
import os
import sys
import logging
from datetime import datetime
import io
import json

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 中文 Windows 下 Python 的默认文件编码是 GBK(cp936)，会导致 web3/eth_utils
# 读取自带的 UTF-8 JSON 时报 UnicodeDecodeError。此处显式检查并给出可操作提示。
# 根治办法：设置环境变量 PYTHONUTF8=1（见 README / 部署文档）。
if not sys.flags.utf8_mode:
    print("⚠️  未启用 UTF-8 模式（PYTHONUTF8=1）。中文 Windows 上可能导致 web3/eth_utils 读取数据文件失败。")
    print("    临时启用：$env:PYTHONUTF8 = '1'    永久启用：setx PYTHONUTF8 1")

# 添加当前目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# 强制设置日志级别 - 在导入任何其他模块之前
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

# 配置详细的日志 - 强制版本
def setup_logging():
    """强制设置详细的日志配置 - 修复编码问题"""

    # 清除所有现有的日志处理器
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # 配置根日志记录器 - 修复编码问题
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            # 修复文件编码问题
            logging.FileHandler('app.log', encoding='utf-8', mode='w')
        ],
        force=True,  # 强制覆盖现有配置
        encoding='utf-8'  # 明确指定编码
    )

    # 强制设置特定库的日志级别
    logging.getLogger('werkzeug').setLevel(logging.INFO)
    logging.getLogger('flask').setLevel(logging.INFO)
    logging.getLogger('__main__').setLevel(logging.INFO)

    # 减少一些不重要的日志
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    logging.getLogger('web3').setLevel(logging.WARNING)

# 立即设置日志
setup_logging()

logger = logging.getLogger(__name__)

# 创建Flask应用
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from sqlalchemy import text

from config import config

# 关键修复：先创建应用实例
app = Flask(__name__)
logger.info("🚀 Flask应用实例已创建")

# 使用配置
app.config['SECRET_KEY'] = config.JWT_SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = config.SQLALCHEMY_TRACK_MODIFICATIONS
app.config['JWT_SECRET_KEY'] = config.JWT_SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = config.JWT_ACCESS_TOKEN_EXPIRES
app.config['DEBUG'] = True  # 启用调试模式

# 强制 Werkzeug 日志级别
import werkzeug
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.INFO)

# 初始化数据库
db = SQLAlchemy(app)

# 初始化JWT
jwt = JWTManager(app)

# ========== 关键修复：先定义所有路由，再注册蓝图 ==========

# 添加自定义的请求日志中间件
@app.before_request
def log_request_details():
    """记录详细的请求信息"""
    if request.path not in ['/api/health', '/favicon.ico']:
        logger.info("=" * 80)
        logger.info(f"📥 收到请求: {request.method} {request.path}")
        logger.info(f"📍 来源: {request.remote_addr} - 时间: {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
        logger.info(f"📋 User-Agent: {request.headers.get('User-Agent', 'Unknown')}")

        # 认证头：只记录是否存在，绝不落盘 token 内容
        auth_header = request.headers.get('Authorization', '')
        logger.info("🔐 认证头: 已提供" if auth_header else "🔐 认证头: 未提供")

        # 记录请求体（如果是JSON）——按白名单遮罩敏感字段，含嵌套结构
        if request.method in ['POST', 'PUT', 'PATCH'] and request.content_type == 'application/json':
            try:
                data = request.get_json(silent=True) or {}
                logger.info(f"📦 请求数据: {json.dumps(_mask_sensitive(data), ensure_ascii=False)}")
            except Exception as e:
                logger.info(f"📦 请求数据解析错误: {e}")

        # 记录查询参数
        if request.args:
            logger.info(f"🔍 查询参数: {dict(request.args)}")

        logger.info("=" * 80)

@app.after_request
def log_response_details(response):
    """记录详细的响应信息"""
    if request.path not in ['/api/health', '/favicon.ico']:
        request_duration = datetime.now() - getattr(request, 'start_time', datetime.now())

        logger.info("=" * 80)
        logger.info(f"📤 响应完成: {request.method} {request.path}")
        logger.info(f"📊 状态码: {response.status_code} - 大小: {response.content_length or 0} 字节")
        logger.info(f"⏱️  处理时间: {request_duration.total_seconds():.3f} 秒")
        logger.info(f"🕒 完成时间: {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")

        # 记录错误响应
        if response.status_code >= 400:
            try:
                response_data = response.get_json(silent=True)
                if response_data:
                    logger.info(f"🚨 错误详情: {json.dumps(response_data, ensure_ascii=False, indent=2)}")
            except:
                pass

        logger.info("=" * 80)

    return response

# 记录请求开始时间
def _mask_sensitive(value, depth=0):
    """递归遮罩敏感字段（spec.md 第 6 节：scores/secret 不得落日志）"""
    if depth > 4:
        return '...'
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(s in lowered for s in ('password', 'secret', 'token', 'key', 'signature', 'scores')):
                out[key] = '***'
            else:
                out[key] = _mask_sensitive(item, depth + 1)
        return out
    if isinstance(value, list):
        return [_mask_sensitive(v, depth + 1) for v in value]
    return value


@app.before_request
def record_start_time():
    request.start_time = datetime.now()

# 修复CORS配置
@app.after_request
def after_request(response):
    """添加CORS头到所有响应"""
    allowed_origins = ['http://localhost:3001', 'http://127.0.0.1:3001']
    origin = request.headers.get('Origin')

    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-CSRF-Token'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'Content-Type, Authorization, X-Total-Count'
        response.headers['Access-Control-Max-Age'] = '86400'

    return response

@app.before_request
def handle_options():
    """处理OPTIONS预检请求"""
    if request.method == 'OPTIONS':
        response = jsonify({
            'status': 'preflight',
            'message': 'CORS preflight request handled'
        })
        allowed_origins = ['http://localhost:3001', 'http://127.0.0.1:3001']
        origin = request.headers.get('Origin')

        if origin in allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-CSRF-Token'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Expose-Headers'] = 'Content-Type, Authorization, X-Total-Count'
            response.headers['Access-Control-Max-Age'] = '86400'

        logger.info(f"🔄 OPTIONS预检请求处理: {request.path}")
        return response

# 错误处理
@app.errorhandler(500)
def internal_error(error):
    logger.error(f"❌ 500错误 - 请求路径: {request.path}, 错误: {str(error)}")
    response = jsonify({
        'success': False,
        'message': '服务器内部错误',
        'error': str(error),
        'timestamp': datetime.now().isoformat()
    })
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
    return response, 500

@app.errorhandler(405)
def method_not_allowed(error):
    logger.error(f"❌ 405错误 - 请求路径: {request.path}, 方法: {request.method}")
    response = jsonify({
        'success': False,
        'message': f'请求方法不允许: {request.method} {request.path}',
        'error': str(error),
        'timestamp': datetime.now().isoformat()
    })
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
    return response, 405

@app.errorhandler(400)
def bad_request(error):
    logger.error(f"❌ 400错误 - 请求路径: {request.path}, 错误: {str(error)}")
    response = jsonify({
        'success': False,
        'message': '请求参数错误',
        'error': str(error),
        'timestamp': datetime.now().isoformat()
    })
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
    return response, 400

@app.errorhandler(401)
def unauthorized(error):
    logger.error(f"❌ 401错误 - 请求路径: {request.path}, 未授权访问")
    response = jsonify({
        'success': False,
        'message': '认证失败，请重新登录',
        'error': str(error),
        'timestamp': datetime.now().isoformat()
    })
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
    return response, 401

@app.errorhandler(403)
def forbidden(error):
    logger.error(f"❌ 403错误 - 请求路径: {request.path}, 权限不足")
    response = jsonify({
        'success': False,
        'message': '权限不足，无法访问此资源',
        'error': str(error),
        'timestamp': datetime.now().isoformat()
    })
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
    return response, 403

# JWT配置回调
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    logger.warning(f"🔄 JWT令牌已过期 - 路径: {request.path}")
    response = jsonify({
        'success': False,
        'message': '令牌已过期'
    })
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
    return response, 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    logger.warning(f"🔄 无效JWT令牌 - 路径: {request.path}, 错误: {error}")
    response = jsonify({
        'success': False,
        'message': '无效令牌'
    })
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
    return response, 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    logger.warning(f"🔄 缺少JWT令牌 - 路径: {request.path}")
    response = jsonify({
        'success': False,
        'message': '缺少认证令牌'
    })
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
    return response, 401

# ========== 核心路由定义 - 必须在蓝图注册之前定义 ==========

# 基本路由
@app.route('/')
def index():
    """API根目录"""
    logger.info("🌐 访问根目录")
    return jsonify({
        'success': True,
        'message': '🚀 零知识密封加权评审系统（ZK-SealedWeigh）后端服务',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat(),
        'endpoints': {
            'documentation': '/',
            'health_check': '/api/health',
            'system_info': '/api/info',
            'debug_routes': '/api/debug/routes',
            'debug_test': '/api/debug/test',
            'simple_test': '/api/simple-test',
            'test_logging': '/api/test-logging',
            'debug_create_voting': '/api/debug/create-voting-test',
            'authentication': '/api/auth',
            'voting_management': '/api/voting',
            'score_management': '/api/scores',
            'weight_management': '/api/weights',
            'blockchain': '/api/blockchain'
        }
    })

@app.route('/api/health')
def health_check():
    """健康检查端点 - 修复编码问题版本"""
    logger.info("❤️ 健康检查请求")
    try:
        # 测试数据库连接
        db_status = "healthy"
        try:
            result = db.session.execute(text('SELECT 1 as test'))
            test_value = result.scalar()
            if test_value == 1:
                db_status = "healthy"
            else:
                db_status = "unhealthy: test query failed"
        except Exception as e:
            db_status = f"unhealthy: {str(e)}"

        # 测试区块链连接 - 修复编码问题
        blockchain_status = "unknown"
        blockchain_info = {}
        try:
            from services.blockchain import blockchain_service
            if blockchain_service.is_connected():
                blockchain_status = "connected"
                # 使用更安全的方式获取区块链信息
                try:
                    blockchain_info = {
                        'network_id': blockchain_service.w3.eth.chain_id,
                        'block_number': blockchain_service.w3.eth.block_number,
                        'contract_address': blockchain_service.contract_address,
                        'accounts_count': len(blockchain_service.get_accounts()) if blockchain_service.get_accounts() else 0
                    }
                except Exception as blockchain_error:
                    logger.warning(f"获取区块链详细信息时出错: {blockchain_error}")
                    blockchain_info = {
                        'network_id': '获取失败',
                        'block_number': '获取失败',
                        'contract_address': blockchain_service.contract_address,
                        'accounts_count': 0
                    }
            else:
                blockchain_status = "disconnected"
        except Exception as e:
            # 修复编码问题：使用安全的错误信息处理
            error_msg = "区块链服务初始化错误"
            try:
                # 尝试安全地获取错误信息
                if hasattr(e, 'args') and e.args:
                    error_msg = str(e.args[0])
                elif hasattr(e, '__str__'):
                    error_msg = e.__str__()
            except:
                pass
            blockchain_status = f"error: {error_msg}"

        response = jsonify({
            'status': 'healthy',
            'service': 'zk-voting-backend',
            'timestamp': datetime.now().isoformat(),
            'dependencies': {
                'database': db_status,
                'blockchain': blockchain_status,
                'blockchain_info': blockchain_info if blockchain_info else None
            },
            'version': '1.0.0',
            'cors': 'enabled'
        })
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        return response
    except Exception as e:
        # 修复顶层错误处理
        error_msg = "健康检查处理错误"
        try:
            if hasattr(e, 'args') and e.args:
                error_msg = str(e.args[0])
            elif hasattr(e, '__str__'):
                error_msg = e.__str__()
        except:
            pass

        logger.error(f"❌ 健康检查失败: {error_msg}")
        response = jsonify({
            'status': 'degraded',
            'service': 'zk-voting-backend',
            'error': error_msg,
            'timestamp': datetime.now().isoformat()
        })
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        return response, 500

# 在路由定义部分添加这个测试路由
@app.route('/api/simple-debug-test')
def simple_debug_test():
    """最简单的调试测试"""
    return jsonify({
        'success': True,
        'message': '简单调试路由工作正常',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/info')
def system_info():
    """系统信息端点"""
    logger.info("ℹ️ 获取系统信息")
    response = jsonify({
        'success': True,
        'data': {
            'system': {
                'name': '零知识密封加权评审系统（ZK-SealedWeigh）',
                'version': '1.0.0',
                'description': '基于 Pedersen 承诺与区块链的密封加权评审系统',
                'timestamp': datetime.now().isoformat()
            },
            'api_status': {
                'authentication': 'JWT Token',
                'cors_enabled': True,
                'blockchain_integrated': True
            },
            'database_config': {
                'server': config.DB_SERVER,
                'database': config.DB_NAME,
                'port': config.DB_PORT,
                'driver': config.DB_DRIVER
            }
        }
    })
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
    return response

# 简单测试端点
@app.route('/api/simple-test', methods=['GET', 'POST', 'OPTIONS'])
def simple_test():
    """简单的测试端点"""
    logger.info("🎯 简单测试端点被调用!")

    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight', 'message': 'OPTIONS handled'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response

    elif request.method == 'POST':
        data = request.get_json(silent=True) or {}
        logger.info(f"📨 收到POST数据: {data}")
        return jsonify({
            'success': True,
            'message': '简单测试POST成功',
            'data': data,
            'method': 'POST'
        })

    else:  # GET
        return jsonify({
            'success': True,
            'message': '简单测试GET成功',
            'method': 'GET'
        })

# 测试日志端点
@app.route('/api/test-logging', methods=['GET', 'POST'])
def test_logging():
    """测试日志输出的端点"""
    logger.info("🧪 测试日志端点被调用")

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        logger.info(f"🧪 收到测试数据: {data}")

        return jsonify({
            'success': True,
            'message': '日志测试成功',
            'data': data,
            'timestamp': datetime.now().isoformat()
        })

    return jsonify({
        'success': True,
        'message': '日志测试端点',
        'endpoints': {
            'GET': '返回此消息',
            'POST': '记录并返回数据'
        }
    })

# 调试创建投票测试端点
@app.route('/api/debug/create-voting-test', methods=['POST', 'OPTIONS'])
@jwt_required()
def debug_create_voting_test():
    """调试创建投票功能"""
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response

    try:
        data = request.get_json()
        logger.info(f"🎯 调试端点收到数据: {data}")

        # 记录详细的请求信息
        logger.info(f"📦 请求头: {dict(request.headers)}")
        logger.info(f"👤 用户身份: {get_jwt_identity()}")

        # 模拟成功响应
        response = jsonify({
            'success': True,
            'message': '调试创建投票成功',
            'data': {
                'id': 999,
                'title': data.get('title', '测试投票'),
                'description': data.get('description', ''),
                'candidates': data.get('candidates', []),
                'voters': data.get('voters', []),
                'test_mode': True
            }
        })
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        return response, 201

    except Exception as e:
        logger.error(f"❌ 调试创建投票失败: {e}", exc_info=True)
        response = jsonify({
            'success': False,
            'message': f'调试失败: {str(e)}'
        })
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        return response, 500

# 调试路由端点
@app.route('/api/debug/routes')
def debug_routes():
    """调试路由信息 - 修复版本"""
    logger.info("🐛 获取路由调试信息")

    try:
        routes = []
        for rule in app.url_map.iter_rules():
            if rule.endpoint != 'static':
                routes.append({
                    'endpoint': rule.endpoint,
                    'methods': list(rule.methods),
                    'path': rule.rule
                })

        # 按路径排序
        routes.sort(key=lambda x: x['path'])

        response = jsonify({
            'success': True,
            'data': {
                'total_routes': len(routes),
                'routes': routes
            }
        })
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        return response

    except Exception as e:
        logger.error(f"路由调试错误: {e}")
        return jsonify({
            'success': False,
            'message': f'获取路由信息失败: {str(e)}'
        }), 500

# 简单的调试测试端点
@app.route('/api/debug/test')
def debug_test():
    """简单的调试测试"""
    return jsonify({
        'success': True,
        'message': '调试路由正常工作',
        'timestamp': datetime.now().isoformat()
    })

# ========== 蓝图注册函数 ==========

def register_blueprints():
    """注册所有蓝图 - 修复版本"""
    try:
        blueprints = []

        logger.info("🔍 开始蓝图注册过程...")

        # 认证蓝图 - 直接导入
        try:
            logger.info("🔍 导入认证蓝图...")
            from routes.auth import auth_bp
            app.register_blueprint(auth_bp, url_prefix='/api/auth')
            blueprints.append(('auth', True))
            logger.info("✅ 认证蓝图注册成功")
        except Exception as e:
            blueprints.append(('auth', False))
            logger.error(f"❌ 认证蓝图注册失败: {e}", exc_info=True)

        # 投票蓝图 - 直接导入
        try:
            logger.info("🔍 导入投票蓝图...")
            from routes.voting import voting_bp
            app.register_blueprint(voting_bp, url_prefix='/api/voting')
            blueprints.append(('voting', True))
            logger.info("✅ 投票蓝图注册成功")
        except Exception as e:
            blueprints.append(('voting', False))
            logger.error(f"❌ 投票蓝图注册失败: {e}", exc_info=True)
            # 不再使用备用版本，直接抛出错误
            raise Exception(f"投票蓝图注册失败: {e}")

        # 评分蓝图 - 直接导入
        try:
            logger.info("🔍 导入评分蓝图...")
            from routes.scores import scores_bp
            app.register_blueprint(scores_bp, url_prefix='/api/scores')
            blueprints.append(('scores', True))
            logger.info("✅ 评分蓝图注册成功")
        except Exception as e:
            blueprints.append(('scores', False))
            logger.error(f"❌ 评分蓝图注册失败: {e}", exc_info=True)

        # 权重蓝图 - 直接导入
        try:
            logger.info("🔍 导入权重蓝图...")
            from routes.weights import weights_bp
            app.register_blueprint(weights_bp, url_prefix='/api/weights')
            blueprints.append(('weights', True))
            logger.info("✅ 权重蓝图注册成功")
        except Exception as e:
            blueprints.append(('weights', False))
            logger.error(f"❌ 权重蓝图注册失败: {e}", exc_info=True)

        # 区块链蓝图 - 直接导入
        try:
            logger.info("🔍 导入区块链蓝图...")
            from routes.blockchain import blockchain_bp
            app.register_blueprint(blockchain_bp, url_prefix='/api/blockchain')
            blueprints.append(('blockchain', True))
            logger.info("✅ 区块链蓝图注册成功")
        except Exception as e:
            blueprints.append(('blockchain', False))
            logger.error(f"❌ 区块链蓝图注册失败: {e}", exc_info=True)

        # 恢复蓝图 - 直接导入
        try:
            logger.info("🔍 导入恢复蓝图...")
            from routes.recovery import recovery_bp
            app.register_blueprint(recovery_bp, url_prefix='/api/recovery')
            blueprints.append(('recovery', True))
            logger.info("✅ 恢复蓝图注册成功")
        except Exception as e:
            blueprints.append(('recovery', False))
            logger.error(f"❌ 恢复蓝图注册失败: {e}", exc_info=True)

        # 统计成功注册的蓝图
        successful = sum(1 for _, status in blueprints if status)
        total = len(blueprints)

        logger.info(f"📊 蓝图注册统计: {successful}/{total} 成功")

        # 打印详细状态
        for name, status in blueprints:
            status_icon = "✅" if status else "❌"
            logger.info(f"  {status_icon} {name}")

        # 如果投票蓝图注册失败，直接抛出异常
        if not any(name == 'voting' and status for name, status in blueprints):
            raise Exception("投票蓝图注册失败，服务无法正常运行")

        return successful > 0

    except Exception as e:
        logger.error(f"❌ 蓝图注册过程失败: {e}", exc_info=True)
        raise

# 初始化应用
def create_app():
    """应用工厂函数"""
    with app.app_context():
        try:
            # 测试数据库连接
            logger.info("🔗 测试数据库连接...")
            db.session.execute(text('SELECT 1'))
            logger.info("✅ 数据库连接成功")
        except Exception as e:
            logger.error(f"❌ 数据库连接失败: {e}")
            print(f"❌ 数据库连接错误: {e}")
            print(f"🔧 连接字符串: {config.SQLALCHEMY_DATABASE_URI.replace(config.DB_PASSWORD, '***')}")

        # 关键诊断：检查当前已注册的路由
        logger.info("🔍 注册蓝图前的路由:")
        for rule in app.url_map.iter_rules():
            if rule.endpoint != 'static':
                logger.info(f"  前: {list(rule.methods)} {rule.rule} -> {rule.endpoint}")

        # 注册蓝图
        logger.info("📝 注册蓝图...")
        try:
            if not register_blueprints():
                logger.warning("⚠️ 部分蓝图注册失败，但服务将继续运行")
        except Exception as e:
            logger.error(f"❌ 蓝图注册失败: {e}")
            raise

        # 关键诊断：检查注册蓝图后的路由
        logger.info("🔍 注册蓝图后的路由:")
        for rule in app.url_map.iter_rules():
            if rule.endpoint != 'static':
                logger.info(f"  后: {list(rule.methods)} {rule.rule} -> {rule.endpoint}")

    return app


@app.errorhandler(404)
def not_found(error):
    logger.error(f"❌ 404错误 - 请求路径: {request.path}, 方法: {request.method}")

    # 特殊处理 /api/voting/undefined 的情况
    if request.path.startswith('/api/voting/undefined'):
        logger.error(f"⚠️ 检测到 undefined 投票ID，可能前端参数传递错误")
        return jsonify({
            'success': False,
            'message': '投票ID参数传递错误，请检查前端代码',
            'hint': '请确保从URL正确获取投票ID参数',
            'timestamp': datetime.now().isoformat()
        }), 400

    response = jsonify({
        'success': False,
        'message': f'请求的资源不存在: {request.path}',
        'error': str(error),
        'timestamp': datetime.now().isoformat()
    })
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
    return response, 404

# ========== 关键修复：确保应用在正确时机运行 ==========
if __name__ == '__main__':
    # 设置环境变量
    os.environ['FLASK_ENV'] = 'development'

    # 创建应用实例
    app_instance = create_app()

    # 启动信息
    print("\n" + "=" * 70)
    print("🚀 零知识密封加权评审系统（ZK-SealedWeigh） - 后端服务")
    print("=" * 70)
    print(f"📡 服务地址: http://127.0.0.1:{config.PORT}")
    print(f"🔗 健康检查: http://127.0.0.1:{config.PORT}/api/health")
    print(f"📊 系统信息: http://127.0.0.1:{config.PORT}/api/info")
    print(f"🐛 路由调试: http://127.0.0.1:{config.PORT}/api/debug/routes")
    print(f"🧪 调试测试: http://127.0.0.1:{config.PORT}/api/debug/test")
    print(f"🧪 创建投票调试: http://127.0.0.1:{config.PORT}/api/debug/create-voting-test")
    print(f"🧪 简单测试: http://127.0.0.1:{config.PORT}/api/simple-test")
    print(f"🧪 日志测试: http://127.0.0.1:{config.PORT}/api/test-logging")
    print(f"🌐 CORS配置: 允许 127.0.0.1:3001 和 localhost:3001")
    print("=" * 70)

    # 显示配置信息
    print(f"🗄️  数据库: {config.DB_SERVER}:{config.DB_PORT}/{config.DB_NAME}")
    try:
        from services.blockchain import blockchain_service
        print(f"⛓️  区块链: {'已连接' if blockchain_service.is_connected() else '未连接'}")
    except:
        print("⛓️  区块链: 未连接")
    print("=" * 70)

    print("📝 日志级别: INFO (详细输出)")
    print("🐛 调试模式: 启用")
    print("🔄 自动重载: 禁用")
    print("=" * 70)

    # 启动服务
    try:
        logger.info("🚀 启动 Flask 应用服务器...")
        app.run(
            debug=True,
            host='127.0.0.1',
            port=config.PORT,
            threaded=True,
            use_reloader=False
        )
    except Exception as e:
        logger.error(f"❌ 服务启动失败: {e}")
        print(f"❌ 错误: {e}")
        sys.exit(1)