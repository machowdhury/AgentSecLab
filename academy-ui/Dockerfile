# syntax=docker/dockerfile:1
# Reproducible, isolated build of the Academy UI. Nothing from the host is mounted: sources are COPYed, and the result leaves through
# `docker build --output`. The base image is pinned by digest, pnpm by exact version, install scripts are disabled, and the real
# `vite build` runs with NO network. No credentials or build secrets are passed.
FROM node@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS base
ENV CI=true NPM_CONFIG_UPDATE_NOTIFIER=false
RUN npm install -g --ignore-scripts pnpm@10.34.3 && mkdir /app && chown node:node /app
WORKDIR /app
USER node

FROM base AS lock
COPY --chown=node:node package.json .npmrc ./
RUN pnpm install --lockfile-only --ignore-scripts
FROM scratch AS lockfile
COPY --from=lock /app/pnpm-lock.yaml /

FROM base AS build
COPY --chown=node:node package.json pnpm-lock.yaml .npmrc ./
RUN pnpm install --frozen-lockfile --ignore-scripts
COPY --chown=node:node . .
RUN pnpm run typecheck
RUN --network=none pnpm run build
FROM scratch AS dist
COPY --from=build /app/dist /
