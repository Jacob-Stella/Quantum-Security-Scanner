import subprocess

#print our interfaces and let user choose scanning interface
def list_interfaces():
    command = ['tshark', '-D']
    result = subprocess.run(command, capture_output=True, text=True)
    if result.stderr:
        print("Error listing interfaces:", result.stderr)
        return None
    else:
        print("Available interfaces:")
        print(result.stdout)
        return result.stdout.splitlines()

#function used to capture tls and ssl handshakes then pipe the data into a csv for processing
def capture_traffic(interface):
    tshark_command = [
        'tshark',
        '-i', interface,
        '-a', 'duration:60',
        '-Y', '((ssl.handshake.type == 1 or ssl.handshake.type == 2 or tls.handshake.type == 1 or tls.handshake.type == 2))',
        '-T', 'fields',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'ipv6.src',
        '-e', 'ipv6.dst',
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
        '-E', 'occurrence=a'
    ]
    output_file_path = 'data/traffic_output.csv'
    with open(output_file_path, 'w') as file:
        result = subprocess.run(tshark_command, stdout=file, stderr=subprocess.PIPE, text=True)
        if result.stderr:
            print("T-Shark Says... \n", result.stderr)
            
def user_select_interface(interfaces):
    choice = int(input("Select an interface by number: "))
    return interfaces[choice - 1].split()[1]

if __name__ == '__main__':
    interfaces = list_interfaces()
    if interfaces:
        interface = user_select_interface(interfaces)
        print("Starting capture on", interface)
        capture_traffic(interface)
