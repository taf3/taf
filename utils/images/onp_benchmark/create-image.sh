#!/bin/bash
if [ -z "$KTEST_DOCKER_REGISTRY" ]; then
    echo "source the SOURCE file"
    exit 2
fi

IMAGE_NAME=onp-bench
IMAGE_VERSION=4


image_name=$IMAGE_NAME:$IMAGE_VERSION

docker build -t $image_name .
docker images
docker tag  $image_name $KTEST_DOCKER_REGISTRY/$image_name
docker tag  $KTEST_DOCKER_REGISTRY/$image_name $KTEST_DOCKER_REGISTRY/$IMAGE_NAME
docker push $KTEST_DOCKER_REGISTRY/$image_name
docker push $KTEST_DOCKER_REGISTRY/$IMAGE_NAME
docker images | grep "<none>" | awk '{print $3}' | xargs docker rmi -f >/dev/null 2>&1
