/// <reference types="node" />
import { writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { type BuildOptions, buildSync, type Metafile, type OutputFile } from "esbuild";
import tsconfig from "./tsconfig.json" with { type: "json" };

interface BuildOutput {
    jsBundle?: string;
    cssBundle?: string;
}

function collectAssets(meta: Metafile, files: OutputFile[]): BuildOutput {
    const paths: BuildOutput = {};
    for (const [path, file] of Object.entries(meta.outputs)) {
        if (file.entryPoint !== undefined) {
            paths.jsBundle = basename(path);
        }

        if (file.cssBundle !== undefined) {
            paths.cssBundle = basename(file.cssBundle);
        }
    }

    const contents: BuildOutput = {};
    for (const entry of files) {
        switch (basename(entry.path)) {
            case paths.jsBundle:
                contents.jsBundle = entry.text;
                break;

            case paths.cssBundle:
                contents.cssBundle = entry.text;
                break;
        }
    }

    return contents;
}

const config = {
    entryPoints: [join("web", "index.tsx")],
    format: "esm",
    outdir: "/fake",
    target: tsconfig.compilerOptions.target,

    bundle: true,
    metafile: true,
    minify: true,
    write: false,

    assetNames: "[hash]",
    chunkNames: "[hash]",
    entryNames: "[hash]",
} as const satisfies BuildOptions;

const { metafile, outputFiles } = buildSync(config);
const { jsBundle, cssBundle } = collectAssets(metafile, outputFiles);

writeFileSync(
    "index.html",
    [
        `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">`,
        `<meta name="viewport" content="width=device-width, initial-scale=1.0">`,
        "<title>Authorization</title>",
        cssBundle?.length ? `<style>${cssBundle.trimEnd()}</style>` : "",
        jsBundle?.length ? `<script type="module">${jsBundle.trimEnd()}</script>` : "",
        "</head><body></body></html>",
    ].join(""),
);
