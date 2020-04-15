clean:
	rm -rf __pycache__
	rm -f *.pyc

setup:
	pip install -r requirements.txt

proto:
	protoc --python_out=. *.proto
