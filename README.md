# Converter between STIX data format and MITRE Navigator format

## Usage:
Create a new branch of main and add as many input files as you want to the `mitre_input` directory. Make a pull request of the main branch. Input files must be in the following format to be processed:

```[filename].yaml```

File contents:
```
stix_dataset_type: [enterprise/mobile/ics]-attack (mandatory)
threat_actor: [threat actor name/alias] (optional)
```
See `mitre_input/example.yaml` for an example.

Once you make a pull request with these input files, the output files will be populated on your branch in a generated `mitre_output` directory as `[filename].json`. 

An output file will not populate if one corresponding to its name already exists in the `mitre_output` directory. 
