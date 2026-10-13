import { DecisionView } from "./DecisionView.jsx";

function TraceDetail({ trace, redact }) {
  return <DecisionView trace={trace} redact={redact} />;
}

export { TraceDetail };
