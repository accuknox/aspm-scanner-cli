REPO=accuknox
IMGNAME=aspmscanner
IMGTAG?=latest
IMG=${REPO}/${IMGNAME}:${IMGTAG}

docker-buildx:
	docker buildx build -f ./Dockerfile . --platform linux/arm64,linux/amd64 -t ${IMG} --push