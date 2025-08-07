REPO=public.ecr.aws/k9v9d5v2
IMGNAME=accuknox-aspm-scanner
IMGTAG?=latest
IMG=${REPO}/${IMGNAME}:${IMGTAG}

docker-buildx:
	docker buildx build -f ./Dockerfile . --platform linux/arm64,linux/amd64 -t ${IMG} --push