# Zagros Dashboard

The React + TypeScript administration dashboard for
[Zagros](https://github.com/ZagrosGM/Zagros) (Chakra UI + Vite).

## Requirements

Node.js ≥ 16.17 (the project is built with npm; `package-lock.json` is
tracked).

## Install

    git clone https://github.com/ZagrosGM/Zagros.git
    cd Zagros/app/dashboard
    npm ci

### Configure app

Copy `example.env` to `.env` then set the backend api address:

    VITE_BASE_API=https://somewhere.com/

#### Environment variables

| Name          | Description                                                                 |
| ------------- | --------------------------------------------------------------------------- |
| VITE_BASE_API | The api url of the deployed backend ([Zagros](https://github.com/ZagrosGM/Zagros)) |

## Start development server

    npm run dev

## Build for production

    npm run build

In production the panel serves the bundle from `app/dashboard/build/` (the
Docker image builds it in a dedicated stage; see the repository-root
`Dockerfile`).

## Contribution

See [`CONTRIBUTING.md`](../../CONTRIBUTING.md) at the repository root.
