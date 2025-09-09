FROM node:24
WORKDIR /app

# Copy package.json first for better caching
COPY package.json ./

RUN apt-get update && apt-get install -y jq

RUN git init && \
    curl -L https://foundry.paradigm.xyz | bash && \
    npm install -g pnpm && \
    . ~/.bashrc && \
    foundryup && \
    forge install

ENV PATH="/root/.foundry/bin:$PATH"

# Copy the rest of the source code (including pnpm-lock.yaml from parent)
COPY . .

# Install dependencies
RUN pnpm install

RUN pnpm compile

CMD ["sh", "-c", "echo Please verify the environment variables and command."]
