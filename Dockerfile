FROM images.home.mtaylor.io/haskell:latest AS dependencies
# Install system dependencies
USER root
RUN apt-get update && apt-get install -y libpq-dev zlib1g-dev \
  && apt-get clean && rm -rf /var/lib/apt/lists/*
# Add metadata files and build dependencies
USER build
ADD --chown=build:build package.yaml package.yaml
ADD --chown=build:build stack.yaml stack.yaml
ADD --chown=build:build stack.yaml.lock stack.yaml.lock
RUN stack build --only-dependencies --system-ghc


FROM images.home.mtaylor.io/haskell:latest AS build
# Install system dependencies
USER root
RUN apt-get update && apt-get install -y libpq-dev zlib1g-dev \
  && apt-get clean && rm -rf /var/lib/apt/lists/*
# Add the source code and build
USER build
COPY --from=dependencies /build/.stack /build/.stack
ADD --chown=build:build . .
RUN stack build --system-ghc --copy-bins


FROM images.home.mtaylor.io/base:latest AS runtime
# Install system dependencies
USER root
RUN apt-get update && apt-get install -y libpq5 zlib1g \
  && apt-get clean && rm -rf /var/lib/apt/lists/* \
  && adduser --system --no-create-home --uid 1000 api
# Copy the built executables
COPY --from=build /build/.local/bin/api-mtaylor-io /usr/local/bin/api-mtaylor-io
# Add the entrypoint
ADD --chown=1000:1000 entrypoint.sh /usr/local/bin/entrypoint.sh
# Set the user
USER api
# Set the entrypoint
ENTRYPOINT ["entrypoint.sh"]
