// A render error stays where it happened: React unmounts the whole tree on an uncaught render error, so one bad
// entry (a record whose archive had "transcripts": null) left the page blank. Around a tab's view and around each
// entry of a list, it shows what failed in place of that part only; `reset` (e.g. the tab, the entry's data) clears it.
import { Component, type ReactNode } from "react";
import { P } from "./kit";

type Props = { children: ReactNode; what: string; reset?: unknown };
type State = { err: Error | null; reset?: unknown };

export class Boundary extends Component<Props, State> {
  state: State = { err: null, reset: this.props.reset };
  static getDerivedStateFromError(err: Error): Partial<State> { return { err }; }
  static getDerivedStateFromProps(p: Props, s: State): Partial<State> | null {
    return p.reset !== s.reset ? { err: null, reset: p.reset } : null;
  }
  componentDidCatch(err: Error) { console.error(`${this.props.what} failed to render:`, err); }
  render() {
    if (this.state.err) return <P size={2} color="red" mt={2} mb={2}>{`${this.props.what} couldn't be shown: ${this.state.err.message || String(this.state.err)}`}</P>;
    return this.props.children;
  }
}
