import { defineConfig, devices } from "@playwright/test";

const appUrl = "http://localhost:8080";

export default defineConfig({
    fullyParallel: true,
    projects: [
        {
            name: "firefox",
            use: {
                baseURL: appUrl,
                ...devices["Desktop Firefox"],
            },
        },
    ],
    reporter: "list",
    testDir: "test",
    testMatch: "**/*.ts",
    webServer: {
        command: "node build.ts && cargo run",
        url: appUrl,
        reuseExistingServer: true,
    },
});
