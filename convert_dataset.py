import stix2
import json

def convert_dataset_main(stix_data, threat_actor_name, output_filepath):
    print("[+]\tParsing STIX data... (this may take some time)")
    bundle = stix2.parse(stix_data, allow_custom=True)

    print(f"[+]\tScanning for threat actor '{threat_actor_name}'...")
    threat_actor = None
    for obj in bundle.objects:
        if obj.get('type') == 'intrusion-set':
            names = [obj.get('name')] + obj.get('aliases') if hasattr(obj, 'aliases') else [obj.get('name')]
            if threat_actor_name.lower() in map(str.lower, names):
                threat_actor = obj
                break

    if not threat_actor:
        print(f"[x]\tThreat actor '{threat_actor_name}' not found in the dataset. Continuing anyway...")

    #todo: efficiency on searching the bundle twice.

    print(f"[+]\tCollecting relationships for threat actor '{threat_actor_name}'...")
    used_technique_ids = set()

    if threat_actor:
        for relationship in bundle.objects:
            if relationship.get('type') == 'relationship' and relationship.get('relationship_type') == 'uses':
                if relationship.get('source_ref') == threat_actor.get('id'):
                    target_obj = next((obj for obj in bundle.objects if obj.get('id') == relationship.get('target_ref')), None)
                    if target_obj and target_obj.get('type') == 'attack-pattern':
                        used_technique_ids.add(target_obj.get('id'))

    print("[+]\tExtracting techniques...")
    techniques = [obj for obj in bundle.objects if obj.get('type') == 'attack-pattern']

    layer_techniques = []

    print("[+]\tCollecting Technique IDs...")
    for technique in techniques:
        technique_id = None

        for external_reference in technique.get('external_references', []):
            if external_reference.get('source_name') == 'mitre-attack':
                technique_id = external_reference.get('external_id')
                break
        if technique_id:
            technique_entry = {"techniqueID": technique_id}
            if technique.get('id') in used_technique_ids:
                technique_entry["color"] = "#ff6666ff"
                technique_entry["comment"] = f"Used by {threat_actor_name}"
            else:
                technique_entry["color"] = "#909190ff"
            layer_techniques.append(technique_entry)

    layer = {
        "versions": {
            "attack": "16",
            "navigator": "5.1.0",
            "layer": "4.5"
        },
        "name": f"Techniques used by {threat_actor_name}",
        "description": f"Techniques used by the threat actor {threat_actor_name}",
        "domain": "enterprise-attack",
        "techniques": layer_techniques,
        "gradient": {
		"colors": [
			"#ff6666ff",
			"#ffe766ff",
			"#8ec843ff"
		],
		"minValue": 0,
		"maxValue": 100
	    },
        "legendItems": [],
        "metadata": [],
        "filters": {
            "platforms": ["Windows", "Linux", "macOS"]
        },
        "sorting": 0
    }


    print("[+]\tWriting to file...")  
    with open(output_filepath, 'w') as f:
        json.dump(layer, f, indent=4)

    print("[+]\tDone!")  

# Test
# convert_dataset_main('enterprise-attack.json', 'Elderwood')