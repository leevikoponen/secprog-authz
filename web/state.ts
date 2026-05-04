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

export const AuthenticationModel = createModel((key: string) => ({
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
            await cookieStore.set(key, token);

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
            const entry = await cookieStore.get(key);
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

            await cookieStore.delete(key);
            this.token.value = null;
        });
    },

    logout(): void {
        this.token.value = null;
        this.loading.wait((_) => cookieStore.delete(key));
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

function copiedQueryParameters(
    source: URLSearchParams,
    fields: string[],
    additional: Record<string, string>,
): URLSearchParams {
    const output = new URLSearchParams(additional);
    for (const name of fields) {
        const value = source.get(name);
        if (value !== null) {
            output.set(name, value);
        }
    }

    return output;
}

export const AuthorizationModel = createModel((token: string) => ({
    loading: new PromiseModel(),

    confirm(event: SubmitEvent): void {
        event.preventDefault();

        this.loading.wait(async (interrupt) => {
            const source = new URLSearchParams(window.location.search);
            const target = source.get("redirect_url") ?? "/";

            const response = await fetch("authorize", {
                signal: interrupt,
                method: "post",
                headers: {
                    "content-type": "text/json",
                    authorization: `Bearer: ${token}`,
                },
                body: JSON.stringify({
                    target,
                    state: source.get("state"),
                    challenge: source.get("code_challenge"),
                }),
            });

            if (!response.ok) {
                return;
            }

            const payload = copiedQueryParameters(source, ["state"], {
                code: await response.text(),
            });

            window.location.href = `${target}?${payload.toString()}`;
        });
    },
}));
