import os
import glob
import yaml
import urllib
import json
from convert_dataset import convert_dataset_main

MITRE_INPUT_DIR = 'mitre_input'
MITRE_OUTPUT_DIR = 'mitre_output'

dataset_urls = {
    'enterprise-attack':'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json',
    'ics-attack':'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/ics-attack/ics-attack.json',
    'mobile-attack':'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/mobile-attack/mobile-attack.json'
}

def process_yaml_files():
    yaml_files = glob.glob(os.path.join(MITRE_INPUT_DIR, '*.yaml'))

    if not yaml_files:
        print('[x]\tNo YAML files found in mitre_input/')
        return

    if not os.path.exists(MITRE_OUTPUT_DIR):
        os.makedirs(MITRE_OUTPUT_DIR)
    
    print(f'[+]\tIdentified input directory {MITRE_INPUT_DIR}, output directory {MITRE_OUTPUT_DIR}.')

    for yaml_file in yaml_files:
        base_name = os.path.splitext(os.path.basename(yaml_file))[0]
        output_file = os.path.join(MITRE_OUTPUT_DIR, f'{base_name}.json')

        if os.path.exists(output_file):
            print(f'[x]\tSkipping {yaml_file}, output file already exists.')
            continue

        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)

        dataset = data.get('stix_dataset_type')

        if not dataset or (dataset not in dataset_urls.keys()):
            print(f'[x]\tNo dataset found in {yaml_file}, or no URL registered')
            exit(3)

        dataset_url = dataset_urls.get(dataset)

        dataset_content = None

        print(f'[+]\tDownloading dataset at url {dataset_url}...')
        with urllib.request.urlopen(dataset_url) as url:
            dataset_content = json.load(url)

        if dataset_content == None:
            print(f"Error! File hasn't populated, error in getting url:{url}")
            exit(4)

        threat_actor = data.get('threat_actor')

        print(f'[+]\tConverting dataset...')
        convert_dataset_main(dataset_content,threat_actor,output_file)

        print(f'[+]\tProcessed {yaml_file} and saved output to {output_file}')

if __name__ == '__main__':
    process_yaml_files()
