.PHONY: test

test:
	docker build -t fuin -f Dockerfile.test .
	docker run fuin