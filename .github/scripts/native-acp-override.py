#!/usr/bin/env python3
import json
from pathlib import Path
import sys
manifest, client = map(Path, sys.argv[1:])
source = "https://github.com/sourcenetwork/backbone.git"
contents = manifest.read_text()
if source in contents:
    raise SystemExit("Orbis root already names the Backbone source; review the local override")
manifest.write_text(contents + '\n[patch.' + json.dumps(source) + ']\nacp-light-client = { path = '
                    + json.dumps(str(client)) + ' }\n')
