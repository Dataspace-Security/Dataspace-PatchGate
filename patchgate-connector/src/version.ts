declare const __CONNECTOR_VERSION__: string | undefined;

/** Injected by the esbuild bundle; "0.0.0-dev" when running from source. */
export const CONNECTOR_VERSION: string = typeof __CONNECTOR_VERSION__ === "string" ? __CONNECTOR_VERSION__ : "0.0.0-dev";
