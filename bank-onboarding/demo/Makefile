.PHONY: demo demo-up demo-check demo-reset demo-rehearse demo-voiceover demo-record demo-render demo-shorten demo-down
NODE ?= node
demo:
	$(NODE) control.mjs demo
demo-up:
	$(NODE) control.mjs up
demo-check:
	$(NODE) control.mjs check
demo-reset:
	$(NODE) control.mjs reset
demo-rehearse:
	$(NODE) record.mjs --rehearse
demo-voiceover:
	$(NODE) control.mjs voiceover
demo-record:
	$(NODE) record.mjs
demo-render:
	$(NODE) assemble.mjs
demo-shorten:
	$(NODE) shorten.mjs
demo-down:
	$(NODE) control.mjs down
