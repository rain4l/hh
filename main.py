import os
import glob
import yaml
import urllib
import json
from convert_dataset import convert_dataset_main

MITRE_INPUT_DIR = 'mitre_input'
MITRE_OUTPUT_DIR = 'mitre_output'

# These urls are directed by mitre to the most up-to-date versions of the STIX jsons
dataset_urls = {
    'enterprise-attack':'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json',
    'ics-attack':'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/ics-attack/ics-attack.json',
    'mobile-attack':'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/mobile-attack/mobile-attack.json'
}

# Main program
def process_yaml_files():

    # Collect all files in the input directory which match the following pattern
    yaml_files = glob.glob(os.path.join(MITRE_INPUT_DIR, '*.yaml'))

    if not yaml_files:
        print('[x]\tNo YAML files found in mitre_input/')
        exit(8)

    # Create directories if they do not exist yet
    if not os.path.exists(MITRE_OUTPUT_DIR):
        os.makedirs(MITRE_OUTPUT_DIR)
    
    print(f'[+]\tIdentified input directory {MITRE_INPUT_DIR}, output directory {MITRE_OUTPUT_DIR}.')

    # Completing the process for each individual file present (provided they've not been done before)
    for yaml_file in yaml_files:
        base_name = os.path.splitext(os.path.basename(yaml_file))[0]
        output_file = os.path.join(MITRE_OUTPUT_DIR, f'{base_name}.json')

        if os.path.exists(output_file):
            print(f'[x]\tSkipping {yaml_file}, output file already exists.')
            break

        # Acquiring the data from the yaml input file
        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)

        try:
            if "stix_dataset_type" not in data.keys():
                print(f'[x]\tInvalid input file contents in: "{yaml_file}". Refer to usage!')
                exit(5)
        except:
            print(f'[x]\tInvalid input file format in: "{yaml_file}". Refer to usage!')
            exit(6)

        dataset = data.get('stix_dataset_type')

        # Ensuring dataset url is present and known to the code
        if not dataset or (dataset not in dataset_urls.keys()):
            print(f'[x]\tNo dataset found in {yaml_file}, or no URL registered')
            exit(3)

        dataset_url = dataset_urls.get(dataset)

        # Domain to pass through for presentation
        domain = dataset

        dataset_content = None

        # Loading the remote file into a json object in the code
        print(f'[+]\tDownloading dataset at url {dataset_url}...')
        try:
            with urllib.request.urlopen(dataset_url) as url:
                dataset_content = json.load(url)
        except:
            print(f'[x]\tFailed to aquire file from URL: "{dataset_url}". Please check URLs')
            exit(7)

        if dataset_content == None:
            print(f"[x]\tError! File hasn't populated, error in getting url:{url}")
            exit(4)

        threat_actor = None
        if "threat_actor" in data.keys():
            threat_actor = data.get('threat_actor')

        # Second "main" part, converting the STIX data to the Nagivator format
        print(f'[+]\tConverting dataset...')
        convert_dataset_main(dataset_content,threat_actor,output_file,domain)

        # Reach here once the whole file has been processed, loop if more than one file
        print(f'[+]\tProcessed {yaml_file} and saved output to {output_file}')

if __name__ == '__main__':
    process_yaml_files()
    exit(0)
