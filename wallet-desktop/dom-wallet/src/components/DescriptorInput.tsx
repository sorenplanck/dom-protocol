// Mode B descriptor paste input — same UX as SlatepackInput, re-exported with a
// descriptor-specific default placeholder for clarity at call sites.
import { SlatepackInput } from "./SlatepackInput";

export function DescriptorInput(props: {
  value: string;
  onChange: (v: string) => void;
  label?: string;
}) {
  return (
    <SlatepackInput
      {...props}
      placeholder="DOMRR1…  (paste the recipient's receive descriptor)"
    />
  );
}
