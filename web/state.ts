import { batch, createModel, effect, signal } from "@preact/signals-core";
import type { TargetedInputEvent } from "preact";

export const PromiseModel = createModel(() => {
    let cancellation: AbortController | undefined;

    effect(() => () => cancellation?.abort());

    return {
        ready: signal(true),
        error: signal<unknown | null>(null),

        wait(action: (interrupt: AbortSignal) => Promise<void>): void {
            batch(() => {
                this.ready.value = false;
                this.error.value = null;
            });

            cancellation?.abort();
            cancellation = new AbortController();

            action(cancellation.signal)
                .catch((error) => (this.error.value = error))
                .finally(() => {
                    cancellation = undefined;
                    this.ready.value = true;
                });
        },
    };
});

export const AuthenticationModel = createModel(() => ({
    loading: new PromiseModel(),

    token: signal<string | null>(null),
    attempted: signal(false),
    registered: signal(false),

    login(username: string, password: string): void {
        this.loading.wait(async (interrupt) => {
            const response = await fetch("login", {
                signal: interrupt,
                method: "post",
                headers: {
                    "content-type": "text/json",
                },
                body: JSON.stringify({ username, password }),
            });

            if (!response.ok) {
                this.attempted.value = true;
                return;
            }

            const token = await response.text();

            batch(() => {
                this.token.value = token;
                this.attempted.value = false;
                this.registered.value = false;
            });
        });
    },

    register(username: string, password: string): void {
        this.loading.wait(async (interrupt) => {
            const response = await fetch("register", {
                signal: interrupt,
                method: "post",
                headers: {
                    "content-type": "text/json",
                },
                body: JSON.stringify({ username, password }),
            });

            if (!response.ok) {
                return;
            }

            batch(() => {
                this.attempted.value = false;
                this.registered.value = true;
            });
        });
    },

    check(): void {
        this.loading.wait(async (interrupt) => {
            const entry = await cookieStore.get("identity-token");
            if (entry?.value === undefined) {
                this.token.value = null;
                return;
            }

            const response = await fetch("check", {
                signal: interrupt,
                headers: {
                    authorization: `Bearer: ${entry.value}`,
                },
            });

            if (response.ok) {
                this.token.value = entry.value;
                return;
            }

            await cookieStore.delete("identity-token");
            this.token.value = null;
        });
    },

    logout(): void {
        this.token.value = null;
        this.loading.wait(async (_) => cookieStore.delete("identity-token"));
    },
}));

export interface LoginBackend {
    login(username: string, password: string): void;
    register(username: string, password: string): void;
}

export const LoginModel = createModel((backend: LoginBackend) => ({
    username: signal(""),
    password: signal(""),
    creating: signal(false),

    update(field: "username" | "password", event: TargetedInputEvent<HTMLInputElement>): void {
        this[field].value = event.currentTarget.value;
    },

    toggle(): void {
        this.creating.value = !this.creating.value;
    },

    finish(event: SubmitEvent): void {
        event.preventDefault();

        if (this.creating.value) {
            backend.register(this.username.value, this.password.value);
        } else {
            backend.login(this.username.value, this.password.value);
        }
    },
}));
