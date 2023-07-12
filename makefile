.PHONY: test

test:
	docker build -t fuin -f Dockerfile.test .
	docker run -v "$$(pwd)/target:/usr/src/fuin/target" fuin