import http.server
import urllib.parse
import os
import sys


class FrontendHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # 解析路径
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        print(f"请求路径: {path}")

        # 处理根路径
        if path == '/':
            self.serve_index()
            return

        # 检查是否是实际文件
        file_path = self.translate_path(path)
        if os.path.isfile(file_path):
            print(f"服务文件: {file_path}")
            super().do_GET()
        else:
            # 前端路由，返回 index.html
            print(f"前端路由: {path} -> index.html")
            self.serve_index()

    def serve_index(self):
        """返回 index.html 用于前端路由"""
        try:
            with open('index.html', 'rb') as f:
                content = f.read()

            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        except Exception as e:
            self.send_error(500, f"Server error: {str(e)}")

    def translate_path(self, path):
        """安全地转换URL路径为文件系统路径"""
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        path = urllib.parse.unquote(path)

        # 防止目录遍历攻击
        if '..' in path:
            path = path.replace('..', '')

        # 构建绝对路径
        abs_path = os.path.abspath(os.path.join(os.getcwd(), path.lstrip('/')))

        # 确保路径在项目目录内
        if not abs_path.startswith(os.getcwd()):
            return os.path.join(os.getcwd(), 'index.html')

        return abs_path

    def log_message(self, format, *args):
        """美化日志输出"""
        client_ip = self.client_address[0]
        request = format % args
        status = request.split('"')[-1].strip()

        if status.startswith('200'):
            status_icon = ''
        elif status.startswith('404'):
            status_icon = ''
        else:
            status_icon = ''

        print(f"{status_icon} {client_ip} - {request}")

    def end_headers(self):
        """添加 CORS 头，并禁用缓存（改样式后无需强刷即可生效）"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()


def run_server():
    PORT = int(os.environ.get('FRONTEND_PORT', 3001))

    # 切换到前端目录
    frontend_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(frontend_dir)

    # 检查必要文件是否存在
    required_files = ['index.html', 'dashboard.html', 'zk-utils.js', 'style.css']
    for file in required_files:
        if not os.path.exists(file):
            print(f"错误: 缺少必要文件 {file}")
            print(f"当前目录: {frontend_dir}")
            print("目录内容:")
            for item in os.listdir('.'):
                print(f"   {item}")
            return

    # 必须用多线程服务器：浏览器会保持 keep-alive 连接并并行请求
    # （snarkjs 要同时拉 wasm/zkey），单线程 TCPServer 会被一个连接阻塞，
    # 表现为页面资源 ERR_ABORTED、刷新卡住。
    with http.server.ThreadingHTTPServer(("127.0.0.1", PORT), FrontendHandler) as httpd:
        print(f"""
ZK评分系统 - 专业前端服务器
================================
服务地址: http://127.0.0.1:{PORT}
工作目录: {frontend_dir}
前端路由: 完全支持
后端地址: http://127.0.0.1:5000

现在可以:
   • 正常创建投票活动
   • 跳转到 admin.html?id=xxx
   • 使用所有前端路由功能
   • 享受稳定的服务

访问: http://127.0.0.1:{PORT}
================================
        """)

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n服务器已安全停止")
        except Exception as e:
            print(f"\n服务器错误: {e}")
            print(f"提示: 请检查端口 {PORT} 是否被占用")


if __name__ == '__main__':
    run_server()