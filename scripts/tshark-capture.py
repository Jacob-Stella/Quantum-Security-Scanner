import subprocess

def capture_traffic():
    tshark_command = [
        'tshark',
        '-i', 'Wi-Fi 2',  # Make sure 'Wi-Fi 2' is the correct interface name on your system.
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
    output_file_path = 'data/traffic_output.csv'
    with open(output_file_path, 'w') as file:
        result = subprocess.run(tshark_command, stdout=file, stderr=subprocess.PIPE, text=True)
        if result.stderr:
            print("Errors encountered during capture:", result.stderr)

if __name__ == '__main__':
    capture_traffic()
