TEST_NETWORK := topsites-proxy

build-sysdig:
	docker pull sysdig/sysdig

build-tcpdump:
	docker build -f Dockerfile.tcpdump -t tcpdump .

run-tcpdump:
	docker run -it --rm -v "$(shell pwd):/tmp" --name tcpdump --net="container:$(TEST_NETWORK)" tcpdump tcpdump -vv -s0 -w "/tmp/$(TEST_NETWORK)-unit.pcap"

run-sysdig:
	docker run -it --rm -v "$(shell pwd):/tmp" --name sysdig --privileged --net=host -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro -e SYSDIG_BPF_PROBE="" sysdig/sysdig sysdig -pc -w "/tmp/$(TEST_NETWORK).scap"

coverage:
	coverage run -m pytest -c pyproject.toml
	coverage report
	coverage html
	python -m webbrowser -t htmlcov/index.html
