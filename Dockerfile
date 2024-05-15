FROM alpine:3.19
# Install system dependencies
USER root
RUN apk add --no-cache gmp libpq zlib \
  && adduser --system --no-create-home --uid 1000 iam
# Copy the built executables
ADD iam-mtaylor-io /usr/local/bin/iam-mtaylor-io
# Copy the migrations
ADD db /usr/local/share/iam-mtaylor-io/db
# Set the user
USER iam
# Set the entrypoint
ENTRYPOINT ["iam-mtaylor-io", "server"]
