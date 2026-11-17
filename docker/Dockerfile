# Build image for ONE isolated build per container.
# Build from the project root:   docker build -f docker/Dockerfile -t apkengine-builder:latest .
# NOT TESTED (no Docker/network where this was written). Review before relying on it.
#
# Building this image accepts the Android SDK license on your behalf (sdkmanager --licenses).
# Read https://developer.android.com/studio/terms first. Do not publish the built image.

FROM eclipse-temurin:8-jdk  AS jdk8
FROM eclipse-temurin:11-jdk AS jdk11
FROM eclipse-temurin:21-jdk AS jdk21
FROM eclipse-temurin:17-jdk

# Optional integrity check: pass the official sha256 shown on the Android command-line tools download page.
ARG CMDLINE_TOOLS_ZIP=commandlinetools-linux-11076708_latest.zip
ARG CMDLINE_TOOLS_SHA256=

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 unzip curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# JDK 17 is the base image (/opt/java/openjdk). The engine also scans /opt/jdks.
COPY --from=jdk8  /opt/java/openjdk /opt/jdks/8
COPY --from=jdk11 /opt/java/openjdk /opt/jdks/11
COPY --from=jdk21 /opt/java/openjdk /opt/jdks/21

ENV ANDROID_HOME=/opt/android-sdk
RUN mkdir -p "$ANDROID_HOME/cmdline-tools" && cd /tmp \
 && curl -fsSLO "https://dl.google.com/android/repository/${CMDLINE_TOOLS_ZIP}" \
 && if [ -n "$CMDLINE_TOOLS_SHA256" ]; then echo "${CMDLINE_TOOLS_SHA256}  ${CMDLINE_TOOLS_ZIP}" | sha256sum -c -; fi \
 && unzip -q "$CMDLINE_TOOLS_ZIP" -d "$ANDROID_HOME/cmdline-tools" \
 && mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest" \
 && rm "$CMDLINE_TOOLS_ZIP"

RUN yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses > /dev/null \
 && "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
      "platform-tools" "platforms;android-34" "platforms;android-35" \
      "build-tools;34.0.0" "build-tools;35.0.0" \
 && chmod -R a+rwX "$ANDROID_HOME"        # the container runs as an arbitrary non-root uid

COPY engine/apkengine.py /app/apkengine.py
RUN mkdir -p /work && chmod 777 /work
ENV HOME=/work
WORKDIR /work
# No ENTRYPOINT: the server runs: python3 /app/apkengine.py build ...
