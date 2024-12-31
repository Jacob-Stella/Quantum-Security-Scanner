import subprocess

def capture_traffic():
    tshark_command = [
        'tshark',
        '-i', 'Wi-Fi',
        '-a', 'duration:30',
        '-Y', '((ssl.handshake.type == 1 or ssl.handshake.type == 2 or tls.handshake.type == 1 or tls.handshake.type == 2))',
        '-T', 'fields',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport',
        '-e', 'tls.handshake.type',
        '-e', 'tls.record.version',
        '-e', 'tls.handshake.version',
        '-e', 'tls.handshake.ciphersuite',
        '-e', 'frame.protocols',
        '-E', 'header=y',
        '-E', 'separator=,',
        '-E', 'quote=d',
        '-E', 'occurrence=f'
    ]
    result = subprocess.run(tshark_command, capture_output=True, text=True, check=True)
    print(result.stdout)
    print(result.stderr)

if __name__ == '__main__':
    capture_traffic()
