interface Props {
  phrase: string;
}

/** Renders a BIP-39 phrase as a numbered grid. Used only transiently during
 *  onboarding / show-seed; the parent is responsible for scrubbing it after. */
export function SeedPhraseDisplay({ phrase }: Props) {
  const words = phrase.trim().split(/\s+/);
  return (
    <div className="seed-grid">
      {words.map((w, i) => (
        <div className="seed-word" key={i}>
          <span className="idx">{i + 1}</span>
          {w}
        </div>
      ))}
    </div>
  );
}
