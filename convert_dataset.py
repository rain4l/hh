import stix2
import json

# "Main" method, called externally
def convert_dataset_main(stix_data, threat_actor_name, output_filepath, domain):

    # Using MITRE's own stix2 library to interpret the STIX data
    print("[+]\tParsing STIX data... (this may take some time)")
    bundle = stix2.parse(stix_data, allow_custom=True)

    threat_actor = None

    # Determining if the threat actor exists in the STIX data, getting all aliases of the actor
    if threat_actor_name != None:
        print(f"[+]\tScanning for threat actor '{threat_actor_name}'...",end="")
        for obj in bundle.objects:
            if obj.get('type') == 'intrusion-set':
                names = [obj.get('name')] + obj.get('aliases') if 'aliases' in obj.keys() else [obj.get('name')]
                if threat_actor_name.lower() in map(str.lower, names):
                    threat_actor = obj
                    # Pretty print if successfully finding the threat actor name in the STIX file
                    print(" Found!")
                    break

        # Code designed to ignore the lack of a threat actor, but note it to the user in the logs (seen in the action logs)
        if not threat_actor:
            print(f"\n[x]\tThreat actor '{threat_actor_name}' not found in the dataset. Continuing anyway...")
    else:
        print(f"[+]\tThreat actor name detected as absent, skipping threat actor identification...")

    print(f"[+]\tProcessing bundle objects...")
    used_technique_ids = set()
    techniques = []

    # If threat_actor is defined, get its ID once
    threat_actor_id = threat_actor.get('id') if threat_actor else None

    # Process bundle.objects in one loop
    for obj in bundle.objects:
        obj_type = obj.get('type')

        # If it's an attack pattern, it goes in techniques
        if obj_type == 'attack-pattern':
            techniques.append(obj)

        # If it's a relationship we care about (our threat actor uses it), store it
        elif obj_type == 'relationship' and obj.get('relationship_type') == 'uses':
            if threat_actor_id and obj.get('source_ref') == threat_actor_id:
                target_ref = obj.get('target_ref')
                used_technique_ids.add(target_ref)

    # Creating a blank layer
    layer_techniques = []

    # Iterating through the techniques, adding them to the layer as we go
    print("[+]\tCollecting Technique IDs...")
    for technique in techniques:
        technique_id = None

        # Getting the reference neessary for proper presentation of the technique in navigator, searching external references
        for external_reference in technique.get('external_references', []):

            # Only mitre-attack sources have external IDs
            if external_reference.get('source_name') == 'mitre-attack':
                technique_id = external_reference.get('external_id')
                break
        
        # If we can find a technique ID, then we can assign it a colour and add it to the layer
        if technique_id:
            technique_entry = {"techniqueID": technique_id}
            if technique.get('id') in used_technique_ids:
                technique_entry["color"] = "#ff6666ff"
                technique_entry["comment"] = f"Used by {threat_actor_name}"
            else:
                technique_entry["color"] = "#909190ff"
            layer_techniques.append(technique_entry)

    # Template taken from a blank layer, modified
    layer = {
        "versions": {
            "attack": "16",
            "navigator": "5.1.0",
            "layer": "4.5"
        },
        "name": f"Techniques used by {threat_actor_name}",
        "description": f"Techniques used by the threat actor {threat_actor_name}",
        "domain": domain,
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
        "sorting": 0
    }

    # Write final output to the known output filepath
    print("[+]\tWriting to file...")  
    with open(output_filepath, 'w') as f:
        json.dump(layer, f, indent=4)

    print("[+]\tDone!")  

# Test
# convert_dataset_main('enterprise-attack.json', 'Elderwood')