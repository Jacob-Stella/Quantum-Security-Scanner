import pandas as pd

def load_cipher_suite_names(csv_file):
    # Load and map cipher suite descriptions from a CSV file.
    cipher_data = pd.read_csv(csv_file)
    cipher_dict = pd.Series(cipher_data['Description'].values, index=cipher_data['Hex Vals'].str.lower()).to_dict()
    return cipher_dict

def load_quantum_resistance(csv_file):
    # Load quantum-resistant cipher suite hex codes from a CSV file.
    qr_data = pd.read_csv(csv_file)
    qr_set = set(qr_data['Hex Code'].str.lower().str.strip())
    return qr_set

def load_approved_ciphers(csv_file):
    # Load approved cipher suites with applicable IPs from a CSV file.
    approved_data = pd.read_csv(csv_file)
    approved_data['Approved IPs'] = approved_data['Approved IPs'].str.lower()
    approved_dict = {row['Hex Code'].lower(): (row['Approved IPs'], row['Description']) for index, row in approved_data.iterrows()}
    return approved_dict

def classify_approved_suites(cipher_suites, approved_dict, ip_src):
     # Determine which cipher suites are approved for the given source IP.
    suites = cipher_suites.split(',')
    approved_suites = []
    for suite in suites:
        suite_cleaned = suite.strip().lower()
        if suite_cleaned in approved_dict:
            approved_ips, description = approved_dict[suite_cleaned]
            if approved_ips == 'all' or ip_src in approved_ips.split(', '):
                approved_suites.append(description)
    return ', '.join(approved_suites)

def enrich_traffic_data(traffic_data, approved_dict):
    # Add classified approved cipher suites to traffic data.
    traffic_data['Approved_Cipher_Suites'] = traffic_data.apply(lambda x: classify_approved_suites(x['tls.handshake.ciphersuite'], approved_dict, x['ip.src']), axis=1)
    return traffic_data


def translate_cipher_suites(cipher_suites, cipher_dict, qr_set, approved_dict, ip_src):
     # Translate, classify, and record details of cipher suites based on their quantum resistance and approval status.
    suites = cipher_suites.split(',')
    translated_suites = []
    qr_suites = []
    non_qr_suites = []
    approved_suites = []
    unapproved_suites = []
    for suite in suites:
        suite_cleaned = suite.strip().lower()
        suite_name = cipher_dict.get(suite_cleaned, 'Unknown Cipher Suite')
        translated_suites.append(suite_name)

        if suite_cleaned in qr_set:
            qr_suites.append(suite_name)
        else:
            non_qr_suites.append(suite_name)

        if suite_cleaned in approved_dict:
            approved_ips, description = approved_dict[suite_cleaned]
            if approved_ips == 'all' or ip_src in approved_ips.split(', '):
                approved_suites.append(description)
        else:
            unapproved_suites.append(suite_name)

    return ', '.join(translated_suites), ', '.join(qr_suites), ', '.join(non_qr_suites), ', '.join(approved_suites), ', '.join(unapproved_suites)

def load_and_analyze(traffic_csv, cipher_csv, quantum_csv, approved_csv):
    # Load data, apply translations and classifications, and generate summaries.
    traffic_data = pd.read_csv(traffic_csv)
    cipher_dict = load_cipher_suite_names(cipher_csv)
    qr_set = load_quantum_resistance(quantum_csv)
    approved_dict = load_approved_ciphers(approved_csv)

    # Apply cipher suite translation, quantum classification, and approval check
    results = traffic_data.apply(lambda x: translate_cipher_suites(x['tls.handshake.ciphersuite'], cipher_dict, qr_set, approved_dict, x['ip.src']), axis=1)
    traffic_data['cipher_suite_name'], traffic_data['Quantum_Resistant_Suites'], traffic_data['Non_Quantum_Resistant_Suites'], traffic_data['Approved_Cipher_Suites'], traffic_data['Unapproved_Cipher_Suites'] = zip(*results)

    # Merge IPv4 and IPv6 addresses into the 'ip.src' and 'ip.dst' fields
    traffic_data['ip.src'] = traffic_data['ip.src'].combine_first(traffic_data['ipv6.src'])
    traffic_data['ip.dst'] = traffic_data['ip.dst'].combine_first(traffic_data['ipv6.dst'])

    # Generate IP summary with additional details
    ip_summary = traffic_data.groupby('ip.src').agg(
        Src_IP=pd.NamedAgg(column='ip.src', aggfunc='first'),
        Connections=pd.NamedAgg(column='ip.dst', aggfunc='size'),
        Cipher_Suites=pd.NamedAgg(column='cipher_suite_name', aggfunc=pd.Series.unique),
        Talked_To_IPs=pd.NamedAgg(column='ip.dst', aggfunc=pd.Series.unique),
        Quantum_Resistant_Suites=pd.NamedAgg(column='Quantum_Resistant_Suites', aggfunc='unique'),
        Non_Quantum_Resistant_Suites=pd.NamedAgg(column='Non_Quantum_Resistant_Suites', aggfunc='unique'),
        Approved_Cipher_Suites=pd.NamedAgg(column='Approved_Cipher_Suites', aggfunc='unique'),
        Unapproved_Cipher_Suites=pd.NamedAgg(column='Unapproved_Cipher_Suites', aggfunc='unique')
    )

    print("Updated data with cipher suite names and approval status:")
    print(traffic_data.head())
    print("IP summary with cipher suite names and approval status:")
    print(ip_summary.head())

    traffic_data.to_csv('data/enriched_traffic_output.csv', index=False)
    ip_summary.to_csv('data/ip_summary_output.csv', index=False)

if __name__ == "__main__":
    traffic_csv_path = 'data/traffic_output.csv'
    cipher_csv_path = 'data/Security-Suite-Data/ciphersuite-hex-vals.csv'
    quantum_csv_path = 'data/Security-Suite-Data/quantum-resistant-cyphers.csv'
    approved_csv_path = 'data/Security-Suite-Data/approved-ciphers.csv'
    load_and_analyze(traffic_csv_path, cipher_csv_path, quantum_csv_path, approved_csv_path)
