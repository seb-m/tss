
clean:
	find . \( -name '*~' -or \
		-name '*.pyc' -or \
		-name '*.pyo' -or \
		-name '#*' -or \
		-name '.#*' -or \
		-name 'MANIFEST' -or \
		-name '*.so' \) \
		-print -exec rm {} \;
	rm -rf dist *build __pycache__
