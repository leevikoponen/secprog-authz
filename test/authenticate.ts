/// <reference types="node" />
import { randomBytes } from "node:crypto";
import { expect, test } from "@playwright/test";

test("full authentication flow works", async ({ context, page }) => {
    const username = randomBytes(8).toString("hex");
    const password = randomBytes(32).toString("hex");
    const incorrect = randomBytes(32).toString("hex");

    await context.clearCookies();
    await page.goto("/");

    await test.step("ensure missing account doesn't work", async () => {
        await page.getByLabel("Username").fill(username);
        await page.getByLabel("Password").fill(password);

        await page.getByText("Sign in").click();

        await expect(page.getByText("Invalid username or password")).toBeVisible();
    });

    await test.step("ensure an account can be created", async () => {
        await page.getByText("Create an account instead").click();

        await page.getByLabel("Username").fill(username);
        await page.getByLabel("Password").fill(password);

        await page.getByText("Create account").click();

        await expect(page.getByText("Account created successfully")).toBeVisible();
    });

    await test.step("ensure incorrect password doesn't work", async () => {
        await page.getByLabel("Username").fill(username);
        await page.getByLabel("Password").fill(incorrect);

        await page.getByText("Sign in").click();

        await expect(page.getByText("Invalid username or password")).toBeVisible();
    });

    await test.step("ensure correct password is accepted", async () => {
        await page.getByLabel("Username").fill(username);
        await page.getByLabel("Password").fill(password);

        await page.getByText("Sign in").click();

        await expect(page.getByText("Signed in successfully")).toBeVisible();
    });

    await test.step("ensure successful authentication is retained", async () => {
        await page.reload();

        await expect(page.getByText("Signed in successfully")).toBeVisible();
    });

    await test.step("ensure signing out gets back to login form", async () => {
        await page.getByText("Sign out").click();

        await expect(page.getByText("Sign in")).toBeVisible();
    });
});
