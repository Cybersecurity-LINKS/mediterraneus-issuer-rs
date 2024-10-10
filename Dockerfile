# ---------------------------------------------------
# 1 - Build Stage
# ---------------------------------------------------

FROM rust:1.81-alpine AS build
WORKDIR /usr/src/app
COPY . .
RUN  apk add --no-cache make musl-dev clang llvm gcc libc-dev clang-dev binutils g++ linux-headers libstdc++ libgcc libressl-dev
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN cargo install --path ./server

# ---------------------------------------------------
# 2 - Deploy Stage
# ---------------------------------------------------

FROM alpine:latest
RUN  apk add --no-cache gcc libgcc libressl-dev
COPY --from=build /usr/local/cargo/bin/issuer /usr/local/bin/issuer
EXPOSE 3213
CMD [ "issuer" ]