cat | xargs -I NUM bash -c "../iflog vifNUM.0 250000 | tee iflogNUM.0 | ../netmonui/netmonui &" 
