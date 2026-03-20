// @ts-expect-error
import "./index.css";
import { render } from "preact";
import { AuthenticationPage } from "./view";

render(<AuthenticationPage />, document.body);
