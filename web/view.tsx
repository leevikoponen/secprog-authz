import { effect, useComputed, useModel } from "@preact/signals";
import { Show } from "@preact/signals/utils";
import type { JSX } from "preact";
import { AuthenticationModel, type LoginBackend, LoginModel } from "./state.ts";

function LoginForm({ backend }: { backend: LoginBackend }): JSX.Element {
    const state = useModel(LoginModel.bind(globalThis, backend));

    return (
        <form onSubmit={state.finish.bind(state)}>
            <label>
                Username
                <input type="text" value={state.username} required />
            </label>

            <label>
                Password
                <input type="password" value={state.username} required />
            </label>

            <button type="button" onClick={state.toggle.bind(state)}>
                {state.creating.value ? "Sign in instead" : "Create an account instead"}
            </button>

            <button type="submit">{state.creating.value ? "Create account" : "Sign in"}</button>
        </form>
    );
}

export function AuthenticationPage(): JSX.Element {
    const state = useModel(AuthenticationModel);
    const hasToken = useComputed(() => state.token.value !== null);
    const fullyAuthenticated = useComputed(() => state.loading.ready.value && hasToken.value);

    effect(state.check.bind(state));

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
                <Show when={state.registered}>
                    <small>Account created successfully</small>
                </Show>

                <Show when={state.loading.ready} fallback={<p>Loading...</p>}>
                    <Show when={hasToken} fallback={<LoginForm backend={state} />}>
                        <p>Signed in successfully</p>
                    </Show>
                </Show>
            </main>
        </>
    );
}
