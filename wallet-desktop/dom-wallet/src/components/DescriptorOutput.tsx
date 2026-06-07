// Mode B descriptor display — reuses SlatepackOutput (copy + QR).
import { SlatepackOutput } from "./SlatepackOutput";

export function DescriptorOutput(props: { value: string; label?: string }) {
  return <SlatepackOutput {...props} />;
}
