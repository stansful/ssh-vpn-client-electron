export function Segmented<T extends string>({
  value,
  options,
  onChange
}: {
  value: T;
  options: Array<[T, string]>;
  onChange: (value: T) => void;
}): JSX.Element {
  return (
    <div className="segmented">
      {options.map(([option, label]) => (
        <button key={option} type="button" className={value === option ? "active" : ""} onClick={() => onChange(option)}>
          {label}
        </button>
      ))}
    </div>
  );
}
