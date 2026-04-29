import { useComputed, useModel, useSignalEffect } from "@preact/signals";
import { Show } from "@preact/signals/utils";
import type { JSX } from "preact";
import { AuthenticationModel, AuthorizationModel, type LoginBackend, LoginModel } from "./state.ts";

function LoginForm({ backend }: { backend: LoginBackend }): JSX.Element {
    const state = useModel(LoginModel.bind(globalThis, backend));

    return (
        <form onSubmit={state.finish.bind(state)}>
            <label>
                Username
                <input
                    type="text"
                    value={state.username}
                    onInput={state.update.bind(state, "username")}
                    required
                />
            </label>

            <label>
                Password
                <input
                    type="password"
                    value={state.password}
                    onInput={state.update.bind(state, "password")}
                    required
                />
            </label>

            <button type="button" onClick={state.toggle.bind(state)}>
                {state.creating.value ? "Sign in instead" : "Create an account instead"}
            </button>

            <button type="submit">{state.creating.value ? "Create account" : "Sign in"}</button>
        </form>
    );
}

export function AuthorizationPage({ token }: { token: string }): JSX.Element {
    const state = useModel(AuthorizationModel.bind(globalThis, token));

    return (
        <Show when={state.loading.ready} fallback={<p>Loading...</p>}>
            <form onSubmit={state.confirm.bind(state)}>
                <button type="submit">Authorize application</button>
            </form>
        </Show>
    );
}

export function AuthenticationPage(): JSX.Element {
    const state = useModel(AuthenticationModel.bind(globalThis, "identity-token"));
    const hasToken = useComputed(() => state.token.value !== null);
    const fullyAuthenticated = useComputed(() => state.loading.ready.value && hasToken.value);

    useSignalEffect(state.check.bind(state));

    return (
        <>
            <header>
                <h1>{document.title}</h1>

                <Show when={fullyAuthenticated}>
                    <button type="button" onClick={state.logout.bind(state)}>
                        Sign out
                    </button>
                </Show>
            </header>

            <main>
                <Show when={state.loading.ready} fallback={<p>Loading...</p>}>
                    <Show when={state.registered}>
                        <small>Account created successfully</small>
                    </Show>

                    <Show when={state.attempted}>
                        <small>Invalid username or password</small>
                    </Show>

                    <Show when={hasToken} fallback={<LoginForm backend={state} />}>
                        <small>Signed in successfully</small>

                        {/** biome-ignore lint/style/noNonNullAssertion: checked above */}
                        <AuthorizationPage token={state.token.value!} />
                    </Show>
                </Show>
            </main>
        </>
    );
}
