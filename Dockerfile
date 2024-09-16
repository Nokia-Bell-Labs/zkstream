FROM zokrates/zokrates:0.8.8 as zokrates

USER root

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gcc \
    libc6-dev \
    wget \
    curl

USER zokrates
WORKDIR /home/zokrates

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/home/zokrates/.cargo/bin:${PATH}"

# Copy the source code
COPY . .
USER root
RUN chown -R zokrates:zokrates .
USER zokrates

# Build all projects, in both debug and release mode
RUN cargo build
RUN cargo build --release

CMD ["/bin/bash"]
